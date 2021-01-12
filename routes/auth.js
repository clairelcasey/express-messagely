"use strict";

const Router = require("express").Router;
const router = new Router();

const { SECRET_KEY } = require("../config");
const { UnauthorizedError, BadRequestError } = require("../expressError");
const User = require("../models/user");
const jwt = require("jsonwebtoken");

/** POST /login: {username, password} => {token} */

router.post("/login", async function (req, res, next) {
  const { username, password } = req.body;
  if (await User.authenticate(username, password)) {
    // iat: Math.floor(Date.now() / 1000)
    // TODO: update user login timestamp on login
    // JWT creates an iat automatically for us
    let token = jwt.sign({ username }, SECRET_KEY);
    return res.json({ token });
  }
  throw new BadRequestError("Invalid user/password");
});

/** POST /register: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 */

router.post("/register", async function (req, res, next) {
  const { username } = await User.register(req.body);
  // TODO: update user login timestamp on login
  let token = jwt.sign({ username }, SECRET_KEY);
  return res.json({ token });
});

module.exports = router;