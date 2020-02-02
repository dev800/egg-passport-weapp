"use strict";
var util = require("util");
var passport = require("passport-strategy");
var debug = require("debug")("passport-weapp");
var OAuth = require('wechat-oauth');

function WeAppStrategy (options, verify) {
  options = options || {};

  if (!verify) {
    throw new TypeError("WeAppStrategy required a verify callback");
  }

  if (typeof verify !== "function") {
    throw new TypeError("_verify must be function");
  }

  if (!options.appID) {
    throw new TypeError("WeAppStrategy requires a appID option");
  }

  if (!options.appSecret) {
    throw new TypeError("WeAppStrategy requires a appSecret option");
  }

  options.isMiniProgram = true
  passport.Strategy.call(this, options, verify);

  this.name = options.name || "weapp";
  this._verify = verify;

  this._oauth = new OAuth(
    options.appID,
    options.appSecret,
    options.saveToken,
    options.getToken,
    options.isMiniProgram
  );

  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from 'passport.Strategy'
 */
util.inherits(WeAppStrategy, passport.Strategy);

/**
 * query:
 *  code
 *  iv
 *  encryptedData
 *  signature
 */
WeAppStrategy.prototype.authenticate = function (req, options) {
  if (!req._passport) {
    return this.error(new Error("passport.initialize() middleware not in use"));
  }

  var self = this;

  options = options || {};

  // 获取code,并校验相关参数的合法性
  // No code only state --> User has rejected send details. (Fail authentication request).
  if (req.query && req.query.state && !req.query.code) {
    return self.fail(401);
  }

  // Documentation states that if user rejects userinfo only state will be sent without code
  // In reality code equals "authdeny". Handle this case like the case above. (Fail authentication request).
  if (req.query && req.query.code === "authdeny") {
    return self.fail(401);
  }

  if (req.query && req.query.action === 'codeToSession') {
    var code = req.query.code;

    if (code) {
      return self._oauth.getSessionKey(code, function (err, response) {
        if (err === null) {
          return self.response({
            status: 200, body: JSON.stringify({
              status: 'ok',
              openid: response.data["openid"],
              unionid: response.data["unionid"],
              sessionKey: response.data["session_key"]
            })
          });
        } else {
          return self.error(err);
        }
      })
    } else {
      return self.response({ status: 422, body: JSON.stringify({ status: 'error', message: 'code missing' }) });
    }
  }

  /**
   * 数据解码
   *   sessionKey
   *   encryptedData: string
   *   iv: string
   */
  if (req.query && req.query.action === 'dataDecrypt') {
    var sessionKey = req.query.sessionKey;
    var iv = req.query.iv;
    var encryptedData = req.query.encryptedData;

    try {
      var decryptData = self._oauth.decryptMiniProgramData({ sessionKey, iv, encryptedData });

      if (decryptData && decryptData.watermark && decryptData.watermark.appid === self._oauth.appid) {
        try {
          return self.response({
            status: 200, body: JSON.stringify({
              status: 'ok',
              decryptData
            })
          });
        } catch (ex) {
          return self.error(ex);
        }
      } else {
        self.fail('encryptedData invalid', 401)
      }
    } catch (err) {
      return self.error(err);
    }
  }

  /**
   * 获取code授权成功
   *   code: string
   *   iv: string
   *   encryptedData: string
   */
  if (req.query && (req.query.code || req.query.sessionKey)) {
    var code = req.query.code;
    var iv = req.query.iv;
    var encryptedData = req.query.encryptedData;

    debug("wechat callback -> \n %s", req.url);

    function verified (err, user, info) {
      if (err) {
        return self.error(err);
      }

      if (!user) {
        return self.fail(info);
      }

      self.success(user, info);
    }

    function authenticate (sessionKey, iv, encryptedData) {
      try {
        var decryptData = self._oauth.decryptMiniProgramData({ sessionKey, iv, encryptedData });

        if (decryptData && decryptData.watermark && decryptData.watermark.appid === self._oauth.appid) {
          var profile = {
            openid: response.data["openid"],
            unionid: response.data["unionid"],
            sessionKey: response.data["session_key"],
            gender: decryptData.gender,
            nickName: decryptData.nickName,
            language: decryptData.language,
            city: decryptData.city,
            province: decryptData.province,
            country: decryptData.country,
            avatarUrl: decryptData.avatarUrl
          };

          try {
            if (self._passReqToCallback) {
              self._verify(req, response.data['access_token'], response.data['refresh_token'], profile, response.data['expires_in'], verified);
            } else {
              self._verify(response.data['access_token'], response.data['refresh_token'], profile, response.data['expires_in'], verified);
            }
          } catch (ex) {
            return self.error(ex);
          }
        } else {
          self.fail('encryptedData invalid', 401)
        }
      } catch (err) {
        return self.error(err);
      }
    }

    if (code) {
      self._oauth.getSessionKey(code, function (err, response) {
        if (err === null) {
          authenticate(response.data["session_key"], iv, encryptedData);
        } else {
          return self.error(err);
        }
      })
    } else {
      authenticate(req.query.sessionKey, iv, encryptedData);
    }
  } else {
    self.fail('code missing', 401);
  }
};

module.exports = WeAppStrategy;
