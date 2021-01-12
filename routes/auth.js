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
    // JWT creates an iat automatically for us
    await User.updateLoginTimestamp(username);
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
  await User.updateLoginTimestamp(username);
  let token = jwt.sign({ username }, SECRET_KEY);
  return res.json({ token });
});

/** POST /forgot-password: { username } => 
 * { message: "Check your phone for a reset code" } 
 **/
// NOTE: could make a jwt out of reset code with expiration date.
// Can validate with jwt -- wouldn't need to store pwd in the database
router.post("/forgot-password", async function (req, res, next) {
  const { username } = req.body;
  const user = await User.updatePasswordCode(username);
  await User.sendPasswordCode(user);
  // Add url on where to visit
  return res.json({ message: "Check your phone for a reset code" });
});

/** POST /update-password: { username, password_code, password } => 
 *  { token }
 **/

router.post("/update-password", async function (req, res, next) {
  const { username, password_code, password } = req.body;
  
  if (await User.authenticatePasswordCode(username, password_code)) {
    await User.updatePassword(username, password);
    let token = jwt.sign({ username }, SECRET_KEY);
    return res.json({ token });
  }

  throw new BadRequestError("Invalid user/password_code");
});

module.exports = router;