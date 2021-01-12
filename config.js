"use strict";

/** Common config for message.ly */

// read .env files and make environmental variables

require("dotenv").config();

const DB_URI = (process.env.NODE_ENV === "test")
    ? "postgresql:///messagely_test"
    : "postgresql:///messagely";

const SECRET_KEY = process.env.SECRET_KEY || "secret";

const ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_NUM = process.env.TWILIO_NUM;
const TO_NUM = process.env.TO_NUM;

const BCRYPT_WORK_FACTOR = 12;


module.exports = {
  DB_URI,
  SECRET_KEY,
  BCRYPT_WORK_FACTOR,
  ACCOUNT_SID,
  AUTH_TOKEN, 
  TWILIO_NUM,
  TO_NUM
};