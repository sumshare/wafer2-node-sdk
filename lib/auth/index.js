const debug = require('debug')('qcloud-sdk[auth]')
const http = require('axios')
const moment = require('moment')
const config = require('../../config')
const qcloudProxyLogin = require('../helper/qcloudProxyLogin')
const AuthDbService = require('../mysql/AuthDbService')
const sha1 = require('../helper/sha1')
const aesDecrypt = require('../helper/aesDecrypt')
    // message常量
const {
    ERRORS,
    LOGIN_STATE
} = require('../constants')

/**
 * 授权模块
 * @param {express request} req
 * @return {Promise}
 * @example 基于 Express
 * authorization(this.req).then(userinfo => { // ...some code })
 */
// 后端登录状态核心
// 还是返回promise
function authorization(req) {
    // 一个典型的登陆请求头
    // 这样一个请求头是由客户端获取用户信息之后包装起来的
    /*
        Accept:* /*
        Accept-Encoding:gzip, deflate, br
        Cache-Control:no-cache
        Connection:keep-alive
        content-type:application/json
    ->  Host:pwcfgsl9.qcloud.la
        Pragma:no-cache
        Referer:https://servicewechat.com/wxf59a70f32de7a00c/devtools/page-frame.html
        User-Agent:wechatdevtools appservice port/9974
    ->  X-WX-Code:011E0xeM01Wvj72a2ldM0sQveM0E0xeU
    ->  X-WX-Encrypted-Data:5isEWgFUI18VVV7QanGGGa8areXe+YTby0EKxe/z3m5wt4UT7d6j/YU4NxZHBkS+WYarZgbKeSeYP5R2wm4QcktztqsKuIdgI2z2s3QwrgY+XyoQk7mOkW+7qCQDnf6pycdSAa4vPTBHxCDr9r8M8plz7S+//TaOAtmERJq6KfUTX0Sdzk5WJhE/rK//iGCPOKRTEKY/Ri9eior+UkD7TDbohxW9qIa2/SUCL+Wi/0VU4JQ/7yZJpvkdoqi1wkBkw3ni9CsnJdRTwFQQjXMp26G54NJi9qrfmZk5gCcw7MFNM7GWCvAqeg3jTgnA8nrEgSrEha9VvA/MwC0WnnIJNLz4nnrqoyWMUsoJxLDUL9M4DQbMjIznip7LPPlC6WbDCWUsOKxNRG1P/V43QX+DGCkP9/ky3c28E8ZPKiN8pXf+lLU6VwBdDqbhWjSgJ3O8qZBvRWxh2SdrMNKeH2Lo5g==
    ->  X-WX-IV:2EHrsf0SCp+J6+/p6iVxqQ==
    */

    // 解构请求头code，encryptedData，iv
    // 唯一的疑问是，解构的范式不分大小写的吗
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

    // code最初的起源来自wx.login返回信息，经过一系列操作放入请求头，请看客户端SDK源码
    // 获取 getSessionKey(code)是一个promise决议值是sessionkey，openid等信息
    return getSessionKey(code)
        .then(pkg => {
            // 其实还能解构出openid，因为pkg就是getSessionKey返回的promise决议
            // 解构session_key
            const {
                session_key
            } = pkg
            // 生成 3rd_session
            // skey和session_key是要存入数据库的，他们之间的关系就是经过sha1加密
            const skey = sha1(session_key)

            // 解密数据
            let decryptedData
            try {
                // aesDecrypt 辅助函数构建userInfo
                // 对称解密用户信息，自己写SDK的话需要从文档了解解密步骤
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
            // userinfo解构是怎么样的，则需要深入数据库操作类库去了解AuthDbService
            // decryptedData就是解密出来的用户信息，存储一波
            // AuthDbService.saveUserInfo操作到最后返回promise，resolve数据是{ userinfo: userInfo,skey: skey}
            // 这波操作让这个函数最终返回promise{loginState:1,userinfo}
            // ES6 允许在对象之中，直接写变量。这时，属性名为变量名, 属性值为变量的值。
            // 方法也可以简写，这个vue里已经见过
            // const o = {
            //   method() {
            //     return "Hello!";
            //   }
            // };
            return AuthDbService.saveUserInfo(decryptedData, skey, session_key).then(userinfo => ({
                    loginState: LOGIN_STATE.SUCCESS,
                    userinfo
                }))
                // 数据库访问返回Promise
                // 总的来说这一步的目的是保存到数据库并返回登录信息
        })
}

/**
 * 鉴权模块
 * @param {express request} req
 * @return {Promise}
 * @example 基于 Express
 * validation(this.req).then(loginState => { // ...some code })
 */
function validation(req) {
    const {
        'x-wx-skey': skey
    } = req.headers
    if (!skey) throw new Error(ERRORS.ERR_SKEY_INVALID)

    debug('Valid: skey: %s', skey)

    return AuthDbService.getUserInfoBySKey(skey)
        .then(result => {
            if (result.length === 0) throw new Error(ERRORS.ERR_SKEY_INVALID)
            else result = result[0]
                // 效验登录态是否过期
            const {
                last_visit_time: lastVisitTime,
                user_info: userInfo
            } = result
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

// 这里是对外暴露的中间件方法
// 看koa-router的文档去
// 正常的中间件都是用async，而async有个特征就是返回值是promise
// 所以即便不用异步函数只要返回值是promise就可以吧
function authorizationMiddleware(ctx, next) {
    //
    return authorization(ctx.req).then(result => {
        // $wxInfo==result=={loginState和userInfo}
        // 
        ctx.state.$wxInfo = result
            // 下一个中间件

        // 或许next()本身是个promise
        // 这里就相当于把next()作为promise的onFullfilled抛出，而authorization本身也return promise
        // 所以authorizationMiddleware的执行结果就是收到一个next()promise
        // 大胆猜测
        // 用 return new promise((resovle,reject)=>{
        //      resolve(next())
        //  })也可以
        return next()
    })



    // 换句话说把这替换成想必也是可以的
    // async function authorizationMiddleware(ctx,next){
    //     await authorization(ctx.req).then(result=>{
    //         ctx.state.$wxInfo = result
    //     });
    //     await next();
    }
}

/**
 * Koa 鉴权中间件
 * 基于 validation 重新封装
 * @param {koa context} ctx koa 请求上下文
 * @return {Promise}
 */
function validationMiddleware(ctx, next) {
    return validation(ctx.req).then(result => {
        ctx.state.$wxInfo = result
        // 多行箭头函数需要加return
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
function getSessionKey(code) {
    // 配置文件是否配置了使用腾讯云代理登录，一般是false，否则需要买腾讯的服务器
    const useQcloudLogin = config.useQcloudLogin

    // 使用腾讯云代小程序登录
    // 大概率是不用的无视这一分支,但是部署时参数随便填，不能为空，否则过不了检验，腾讯服务器解决方案是默认帮你配置好参数的
    if (useQcloudLogin) {
        // 解构腾讯云的ID密码
        const {
            qcloudSecretId,
            qcloudSecretKey
        } = config
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

    // 不使用腾讯代理的话，区别在于哪里呢
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
        // http 是axios,返回promise规范
        // 官方API，返回值在前几行注释里
        // 在这里返回一个promise
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
                // 结束链式 
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