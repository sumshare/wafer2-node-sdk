const debug = require('debug')('qcloud-sdk[auth]')
const http = require('axios')
const moment = require('moment')
const config = require('../../config')
const qcloudProxyLogin = require('../helper/qcloudProxyLogin')
const AuthDbService = require('../mysql/AuthDbService')
const sha1 = require('../helper/sha1')
const aesDecrypt = require('../helper/aesDecrypt')
// message常量
const { ERRORS, LOGIN_STATE } = require('../constants')

/**
 * 授权模块
 * @param {express request} req
 * @return {Promise}
 * @example 基于 Express
 * authorization(this.req).then(userinfo => { // ...some code })
 */
function authorization (req) {
    // 一个登陆请求头
    /*
        Accept:* /*
        Accept-Encoding:gzip, deflate, br
        Cache-Control:no-cache
        Connection:keep-alive
        content-type:application/json
        Host:pwcfgsl9.qcloud.la
        Pragma:no-cache
        Referer:https://servicewechat.com/wxf59a70f32de7a00c/devtools/page-frame.html
        User-Agent:wechatdevtools appservice port/9974
        X-WX-Code:011E0xeM01Wvj72a2ldM0sQveM0E0xeU
        X-WX-Encrypted-Data:5isEWgFUI18VVV7QanGGGa8areXe+YTby0EKxe/z3m5wt4UT7d6j/YU4NxZHBkS+WYarZgbKeSeYP5R2wm4QcktztqsKuIdgI2z2s3QwrgY+XyoQk7mOkW+7qCQDnf6pycdSAa4vPTBHxCDr9r8M8plz7S+//TaOAtmERJq6KfUTX0Sdzk5WJhE/rK//iGCPOKRTEKY/Ri9eior+UkD7TDbohxW9qIa2/SUCL+Wi/0VU4JQ/7yZJpvkdoqi1wkBkw3ni9CsnJdRTwFQQjXMp26G54NJi9qrfmZk5gCcw7MFNM7GWCvAqeg3jTgnA8nrEgSrEha9VvA/MwC0WnnIJNLz4nnrqoyWMUsoJxLDUL9M4DQbMjIznip7LPPlC6WbDCWUsOKxNRG1P/V43QX+DGCkP9/ky3c28E8ZPKiN8pXf+lLU6VwBdDqbhWjSgJ3O8qZBvRWxh2SdrMNKeH2Lo5g==
        X-WX-IV:2EHrsf0SCp+J6+/p6iVxqQ==
    */
    const {
        'x-wx-code': code,
        'x-wx-encrypted-data': encryptedData,
        'x-wx-iv': iv
    } = req.headers

    // 检查 headers
    if ([code, encryptedData, iv].some(v => !v)) {
        debug(ERRORS.ERR_HEADER_MISSED)
        throw new Error(ERRORS.ERR_HEADER_MISSED)
    }

    debug('Auth: code: %s, encryptedData: %s, iv: %s', code, encryptedData, iv)

    // 获取 session key
    return getSessionKey(code)
        .then(pkg => {
            // 解构session_key
            const { session_key } = pkg
            // 生成 3rd_session
            const skey = sha1(session_key)

            // 解密数据
            let decryptedData
            try {
                // aesDecrypt 辅助函数构建userInfo
                decryptedData = aesDecrypt(session_key, iv, encryptedData)
                decryptedData = JSON.parse(decryptedData)
            } catch (e) {
                debug('Auth: %s: %o', ERRORS.ERR_IN_DECRYPT_DATA, e)
                throw new Error(`${ERRORS.ERR_IN_DECRYPT_DATA}\n${e}`)
            }

            // 存储到数据库中
            // cSessionInfo这张表
            // 数据库测试环境密码为APPID
            // 前往查看数据库操作SDK
            return AuthDbService.saveUserInfo(decryptedData, skey, session_key).then(userinfo => ({
                loginState: LOGIN_STATE.SUCCESS,
                userinfo
            }))
            // 数据库访问返回Promise
        })
}

/**
 * 鉴权模块
 * @param {express request} req
 * @return {Promise}
 * @example 基于 Express
 * validation(this.req).then(loginState => { // ...some code })
 */
function validation (req) {
    const { 'x-wx-skey': skey } = req.headers
    if (!skey) throw new Error(ERRORS.ERR_SKEY_INVALID)

    debug('Valid: skey: %s', skey)

    return AuthDbService.getUserInfoBySKey(skey)
        .then(result => {
            if (result.length === 0) throw new Error(ERRORS.ERR_SKEY_INVALID)
            else result = result[0]
            // 效验登录态是否过期
            const { last_visit_time: lastVisitTime, user_info: userInfo } = result
            const expires = config.wxLoginExpires && !isNaN(parseInt(config.wxLoginExpires)) ? parseInt(config.wxLoginExpires) * 1000 : 7200 * 1000

            if (moment(lastVisitTime, 'YYYY-MM-DD HH:mm:ss').valueOf() + expires < Date.now()) {
                debug('Valid: skey expired, login failed.')
                return {
                    loginState: LOGIN_STATE.FAILED,
                    userinfo: {}
                }
            } else {
                debug('Valid: login success.')
                return {
                    loginState: LOGIN_STATE.SUCCESS,
                    userinfo: JSON.parse(userInfo)
                }
            }
        })
}

/**
 * Koa 授权中间件
 * 基于 authorization 重新封装
 * @param {koa context} ctx koa 请求上下文
 * @return {Promise}
 */
// ctx.state: 推荐的命名空间，用来保存那些通过中间件传递给试图的参数或数据。比如 this.state.user = yield User.find(id);

// 还需要掌握关键思想，运行结果是怎么被传递过来的
// Promise的处理机制
function authorizationMiddleware (ctx, next) {
    return authorization(ctx.req).then(result => {
        // $wxInfo==result==loginState和userInfo
        // 
        ctx.state.$wxInfo = result
        return next()
    })
}

/**
 * Koa 鉴权中间件
 * 基于 validation 重新封装
 * @param {koa context} ctx koa 请求上下文
 * @return {Promise}
 */
function validationMiddleware (ctx, next) {
    return validation(ctx.req).then(result => {
        ctx.state.$wxInfo = result
        return next()
    })
}

/**
 * session key 交换
 * @param {string} appid
 * @param {string} appsecret
 * @param {string} code
 * @return {Promise}
 */
function getSessionKey (code) {
    const useQcloudLogin = config.useQcloudLogin

    // 使用腾讯云代小程序登录
    if (useQcloudLogin) {
        const { qcloudSecretId, qcloudSecretKey } = config
        return qcloudProxyLogin(qcloudSecretId, qcloudSecretKey, code).then(res => {
            res = res.data
            console.log(res)
            if (res.code !== 0 || !res.data.openid || !res.data.session_key) {
                debug('%s: %O', ERRORS.ERR_GET_SESSION_KEY, res)
                throw new Error(`${ERRORS.ERR_GET_SESSION_KEY}\n${JSON.stringify(res)}`)
            } else {
                debug('openid: %s, session_key: %s', res.data.openid, res.data.session_key)
                return res.data
            }
        })
    } else {
        const appid = config.appId
        const appsecret = config.appSecret
        // code的获取详细看小程序的开放API文档，有关登录获取code的模块，在客户端SDK的doLogin函数中的request
        // 参照官方文档的逻辑步骤，这些步骤是高度概括的，里面有大量的细节在程序中得到体现
        // 前后台通看，大体会对此有初步认知
        // 所以code的获取逻辑可以稍后再去探究，先继续把这段逻辑走完
        // code 换取 session_key
        // https://api.weixin.qq.com/sns/jscode2session?appid=APPID&secret=SECRET&js_code=JSCODE&grant_type=authorization_code
        //  正常返回的JSON数据包
            // {
            //       "openid": "OPENID",
            //       "session_key": "SESSIONKEY"
            //       "unionid":  "UNIONID"
            // }
            // //错误时返回JSON数据包(示例为Code无效)
            // {
            //     "errcode": 40029,
            //     "errmsg": "invalid code"
            // }
        return http({
            url: 'https://api.weixin.qq.com/sns/jscode2session',
            method: 'GET',
            params: {
                appid: appid,
                secret: appsecret,
                js_code: code,
                grant_type: 'authorization_code'
            }
        }).then(res => {
            res = res.data
            if (res.errcode || !res.openid || !res.session_key) {
                debug('%s: %O', ERRORS.ERR_GET_SESSION_KEY, res.errmsg)
                throw new Error(`${ERRORS.ERR_GET_SESSION_KEY}\n${JSON.stringify(res)}`)
            } else {
                debug('openid: %s, session_key: %s', res.openid, res.session_key)
                return res
            }
        })
    }
}

module.exports = {
    authorization,
    validation,
    authorizationMiddleware,
    validationMiddleware
}
