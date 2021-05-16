const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const validUsernameRegex = /^[a-zA-Z0-9_-]+$/;
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jsonfile = require("jsonfile");
import { createUserData, getUserData, setUserData } from "./user-data";
import { showConsoleError } from "../utils/console-utils";
import { capture } from "../utils/async-utils";
import { getReservedWordInfo } from "../utils/get-reserved-word-info";
import { sendEmail } from "../utils/send-email";

function initUserAccounts({ app }) {
  const JwtStrategy = require('passport-jwt').Strategy;

  const cookieExtractor = function(req) {
    if (req && req.cookies) {
      return req.cookies['__session'];
    }
    return null;
  };

  // get public key from Saasform, e.g. http://localhost:7000/api/v1/public-key
  const key = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEE7lrwY8Ri8zVtx3/EOReJK4ucjxadgra\npDmvW7G7mjxhNLOdfhZK7/E/0RHMEvq5w/UmS84dij0VdJWu1Tgjyg==\n-----END PUBLIC KEY-----";
  const opts = {
    jwtFromRequest: cookieExtractor,
    secretOrKey: key,
    algorithms: ['ES256'],
    ignoreExpiration: false,
  };

  passport.use(new JwtStrategy(opts, async (jwtPayload, done) => {
    let appName;  //TODO we don't have access to req here, not sure how to handle multi-tenancy
    const username = jwtPayload.username
    const email = jwtPayload.email

    // optional, keep Remake db in sync
    let [currentUser] = await capture(getUserData({ username, appName }));
    if (!currentUser) {
      const hash = 'x'
      let [newUser, newUserError] = await capture(createUserData({ appName, username, hash, email }));
    }

    // generally we'd return jwtPayload, but Remake uses .details
    const user = { details: jwtPayload };
    return done(null, user)
  }));

  app.use(passport.initialize());
  app.use(passport.authenticate('jwt', { session: false }));
}

export { initUserAccounts };
