"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const debug = require("debug")("egg-passport-weapp");
const assert = require("assert");
const Strategy = require("./lib/passport-weapp/index").Strategy;

function mountOneClient (config, app, client = "weapp") {
  config.passReqToCallback = true;

  config.successResponse = config.successResponse || function(_req, res) {
    res.statusCode = 200;
    res.body = JSON.stringify({status: 'ok'})
    res.end();
  }

  assert(config.key, "[egg-passport-weapp] config.passportWeapp.key required");
  assert(config.secret, "[egg-passport-weapp] config.passportWeapp.secret required");

  app.passport.use(client, new Strategy(Object.assign({}, config, { appID: config.key, appSecret: config.secret }), (req, accessToken, refreshToken, profile, expiresIn, verified) => {
    profile._raw = JSON.stringify(profile)

    const user = {
      providerPlatform: "wechat",
      providerMedia: "weapp",
      provider: client,
      id: profile.unionid || profile.openid,
      name: profile.nickName,
      displayName: profile.nickName,
      photo: profile.avatarUrl,
      gender: profile.gender === 1 ? "male" : (profile.gender === 2 ? "female" : "unknown"),
      expiresIn,
      accessToken,
      refreshToken,
      sessionKey: profile.sessionKey,
      profile
    };

    debug("%s %s get user: %j", req.method, req.url, user);
    app.passport.doVerify(req, user, verified);
  }));
}
exports.default = (app) => {
  const config = app.config.passportWeapp;

  if (config.clients) {
    for (const client in config.clients) {
      const c = config.clients[client];

      if (config.state) {
        c.state = config.state
      }

      if (config.client) {
        c.client = config.client
      }

      mountOneClient(c, app, client);
    }
  } else {
    mountOneClient(config, app);
  }
};
