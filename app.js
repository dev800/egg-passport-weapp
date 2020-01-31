"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const debug = require("debug")("egg-passport-weapp");
const assert = require("assert");
const Strategy = require("./lib/passport-weapp/index").Strategy;

function mountOneClient (config, app, client = "weapp") {
  config.passReqToCallback = true;

  assert(config.key, "[egg-passport-weapp] config.passportWeapp.key required");
  assert(config.secret, "[egg-passport-weapp] config.passportWeapp.secret required");

  app.passport.use(client, new Strategy(Object.assign({}, config, { appID: config.key, appSecret: config.secret }), (req, accessToken, refreshToken, profile, expires_in, verified) => {
    const user = {
      providerPlatform: "wechat",
      providerGroup: "weapp",
      provider: client,
      id: profile.unionid || profile.openid,
      name: profile.unionid || profile.openid,
      displayName: profile.unionid || profile.openid,
      photo: "",
      gender: profile.gender === "FEMALE"
        ? "female"
        : profile.gender === "MALE"
          ? "male"
          : "unknown",
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
