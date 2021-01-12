"use strict";

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { BadRequestError, NotFoundError } = require("../expressError");

const db = require("../db");
const { ACCOUNT_SID, 
        AUTH_TOKEN, 
        TWILIO_NUM, 
        TO_NUM, 
        SECRET_KEY, 
        BCRYPT_WORK_FACTOR
      } = require("../config");

const client = require('twilio')(ACCOUNT_SID, AUTH_TOKEN);

/** User of the site. */

class User {
  /** Register new user. Returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    let result;
    try {
      result = await db.query(
        `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
             VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
             RETURNING username, password, first_name, last_name, phone`,
        [username, hashedPassword, first_name, last_name, phone]
      );
    } catch (err) {
      throw new BadRequestError(`Unable to add ${username} to database`);
    }

    const user = result.rows[0];
    return user;
  }

  /** Authenticate: is username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      "SELECT password FROM users WHERE username = $1",
      [username]
    );
    let user = result.rows[0];

    // alternate way of returning
    return (
      Boolean(user) && (await bcrypt.compare(password, user.password)) === true
    );

    // if (user) {
    //   if (await bcrypt.compare(password, user.password) === true) {
    //     return true;
    //   }
    // }
    // return false;
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
       SET last_login_at = current_timestamp
         WHERE username = $1
         RETURNING username`,
      [username]
    );

    const user = result.rows[0];
    if (user === undefined) {
      throw new NotFoundError(`no user found with username: ${username}`);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name
           FROM users
           ORDER BY last_name, first_name`
    );
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
           FROM users
           WHERE username = $1`,
      [username]
    );

    const user = results.rows[0];
    if (user === undefined) {
      throw new NotFoundError(`no user found with username: ${username}`);
    }
    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const mResults = await db.query(
      `SELECT     m.id,
                  m.to_username,
                  t.first_name AS to_first_name,
                  t.last_name AS to_last_name,
                  t.phone AS to_phone,
                  m.body,
                  m.sent_at,
                  m.read_at
             FROM messages AS m
                    JOIN users AS t ON m.to_username = t.username
             WHERE m.from_username = $1`,
      [username]
    );

    const messages = mResults.rows;
    return messages.map((m) => ({
      id: m.id,
      to_user: {
        username: m.to_username,
        first_name: m.to_first_name,
        last_name: m.to_last_name,
        phone: m.to_phone,
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at,
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const mResults = await db.query(
      `SELECT     m.id,
                  m.from_username,
                  f.first_name AS from_first_name,
                  f.last_name AS from_last_name,
                  f.phone AS from_phone,
                  m.body,
                  m.sent_at,
                  m.read_at
             FROM messages AS m
                    JOIN users AS f ON m.from_username = f.username
             WHERE m.to_username = $1`,
      [username]
    );

    const messages = mResults.rows;
    return messages.map((m) => ({
      id: m.id,
      from_user: {
        username: m.from_username,
        first_name: m.from_first_name,
        last_name: m.from_last_name,
        phone: m.from_phone,
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at,
    }));
  }

  /** 
   * Updates password_code in users table with time it was generated,
   * given a username
   * returns user or throws NotFoundError 
   **/  

  static async updatePasswordCode(username) {
    const randCode = String(Math.floor(100000 + Math.random() * 900000));
    const hashedPWCode = await bcrypt.hash(randCode, BCRYPT_WORK_FACTOR);
    
    const result = await db.query(
      `UPDATE users
        SET password_code = $1,
            last_generated_at = current_timestamp
          WHERE username = $2
          RETURNING username, password_code, last_generated_at, phone`,
      [hashedPWCode, username]
    );

    const user = result.rows[0];
    if (user === undefined)
      throw new NotFoundError(`no user found with username: ${username}`);
    
    user.actual_password_code = randCode;
    return user;
  }

  /**
   * Method sends Twilio SMS message with 6 digit verification code
   * for a user
   **/

  static async sendPasswordCode(user) {
    const { actual_password_code, phone } = user;

    const message = await client.messages
      .create({
        body: `Your new password code is: ${actual_password_code}`,
        from: TWILIO_NUM,
        to: TO_NUM
      });
    console.log("Sent message to user: ", actual_password_code);
  }

  /** 
   * AuthenticatePasswordCode: is username/password_code valid? Returns boolean.
   */

  static async authenticatePasswordCode(username, password_code) {
    const result = await db.query(
      "SELECT password_code FROM users WHERE username = $1",
      [username]
    );
    let user = result.rows[0];

    return (
      Boolean(user) && 
      (await bcrypt.compare(password_code, user.password_code)) === true
    );
  }

    /** Update password for user */

    static async updatePassword(username, password) {
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
      const result = await db.query(
        `UPDATE users
         SET password = $1
           WHERE username = $2
           RETURNING username`,
        [hashedPassword, username]
      );
  
      const user = result.rows[0];
      if (user === undefined) {
        throw new NotFoundError(`no user found with username: ${username}`);
      }
    }

}

module.exports = User;
