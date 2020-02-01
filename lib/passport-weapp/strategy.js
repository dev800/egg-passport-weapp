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

  // 获取code授权成功
  if (req.query && req.query.code) {
    var code = req.query.code;
    var iv = req.query.iv;
    var encryptedData = req.query.encryptedData;

    debug("wechat callback -> \n %s", req.url);

    self._oauth.getSessionKey(code, function (err, response) {
      function verified (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      }

      if (err === null) {
        try {
          var decryptInfo = self._oauth.decryptMiniProgramUser({ sessionKey: response.data["session_key"], iv, encryptedData });

          if (decryptInfo && decryptInfo.watermark && decryptInfo.watermark.appid === self._oauth.appid) {
            var profile = {
              openid: response.data["openid"],
              unionid: response.data["unionid"],
              sessionKey: response.data["session_key"],
              gender: decryptInfo.gender,
              nickName: decryptInfo.nickName,
              language: decryptInfo.language,
              city: decryptInfo.city,
              province: decryptInfo.province,
              country: decryptInfo.country,
              avatarUrl: decryptInfo.avatarUrl
            };

            var verifyResult;

            try {
              if (self._passReqToCallback) {
                verifyResult = self._verify(req, response.data['access_token'], response.data['refresh_token'], profile, response.data['expires_in'], verified);
              } else {
                verifyResult = self._verify(response.data['access_token'], response.data['refresh_token'], profile, response.data['expires_in'], verified);
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
      } else {
        return self.error(err);
      }
    })
  } else {
    self.fail('code missing', 401);
  }
};

module.exports = WeAppStrategy;
