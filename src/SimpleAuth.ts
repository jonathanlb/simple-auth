import bcrypt = require('bcrypt');
import crypto = require('crypto');
import Debug = require('debug');
import fs = require('fs');
import jwt = require('jsonwebtoken');
import sqlite3 = require('sqlite3-promise');
import SqlString = require('sqlstring');

import {
  Authorizer,
  Credentials,
  SIMPLE_AUTH_ERRORS,
  Session,
  SimpleAuthConfig,
  UserInfo,
} from './types';

const SALT_ROUNDS = 10;
const SESSION_BYTES = 20;
const SESSION_EXPIRY_MS = 86400000; // 24 hours
const SIGN_ALGORITHM = 'RS256'; // for ssh-keygen -t rsa ... ; openssl rsa
const TEMP_PASSWORD_LENGTH = 8;

const debug = Debug('SimpleAuth');
const errors = Debug('SimpleAuth:error');

const INVALID_SESSION: Session = {
  email: '',
  id: '-1',
  session: '',
};

function invalidSession(): Session {
  return Object.assign({}, INVALID_SESSION);
}

export class SimpleAuth implements Authorizer {
  db: sqlite3.Database;
  sqliteFile: string;
  privateKey: string;
  privateKeyFileName: string;
  publicKey: string;
  publicKeyFileName: string;

  constructor(config: SimpleAuthConfig) {
    this.sqliteFile = config.dbFileName;
    this.db = {} as sqlite3.Database;
    this.privateKey = '';
    this.privateKeyFileName = config.privateKeyFileName;
    this.publicKey = '';
    this.publicKeyFileName = config.publicKeyFileName;
  }

  async authenticateSession(sessionObj: Session) {
    try {
      const { session } = sessionObj;
      const [header, payload, sig] = session.split('.');
      debug('auth', header, payload, sig);
      if (!payload || !sig) {
        return false;
      }
      const payloadObj = JSON.parse(Buffer.from(payload, 'base64').toString());
      debug('payloadObj', payloadObj);
      const { email, exp } = payloadObj;
      const headerObj = JSON.parse(Buffer.from(header, 'base64').toString());
      debug('headerObj', headerObj);
      const { clockTimestamp } = headerObj;

      if (exp < new Date().getTime() / 1000) {
        throw new SIMPLE_AUTH_ERRORS.ExpiredSession(exp);
      }

      const verifyOpts = {
        algorithm: headerObj.alg,
        audience: email || '',
      };
      debug('verify', session, verifyOpts);
      const publicKey = await this.getPublicKey();
      const decoded = jwt.verify(session, publicKey, verifyOpts);
      debug('decoded', decoded);
      if (this.validateSessionPayload(sessionObj, decoded)) {
        return decoded;
      } else {
        return false;
      }
    } catch (e) {
      errors('authenticateSession', e.message);
      return false;
    }
  }

  async authenticateUser(credentials: Credentials): Promise<Session> {
    debug('authenticateUser', credentials);
    let query =
      'SELECT email, id, secret, recovery, recoveryExpiry FROM identities ';

    if (credentials.id) {
      query += `WHERE id=${credentials.id}`;
    } else if (credentials.name) {
      query += `WHERE name=${SqlString.escape(credentials.name)}`;
    } else if (credentials.email) {
      query += `WHERE email=${SqlString.escape(credentials.email)}`;
    } else {
      return Promise.resolve(invalidSession());
    }

    debug(query);
    // tslint:disable-next-line:no-any
    const user = (await this.db.getAsync(query)) as any;
    if (!user || !user.secret) {
      debug('found user, no password hashed', user);
      return Promise.resolve(invalidSession());
    }

    if (await bcrypt.compare(credentials.password, user.secret)) {
      debug('password OK', user);
      return this.updateSession(user.id, user.email);
    }

    if (user.recoveryExpiry < new Date().getTime() / 1000) {
      debug('hint expired', user);
      return Promise.resolve(invalidSession());
    }
    if (await bcrypt.compare(credentials.password, user.recovery)) {
      debug('hint OK, resetting password', user);
      await this.setPassword(user.id, credentials.password);
      return this.updateSession(user.id, user.email);
    }

    debug('found user, invalid password/hint', user);
    return Promise.resolve(invalidSession());
  }

  async close() {
    await this.db.close();
    debug('close');
    this.db = {} as sqlite3.Database;
    return;
  }

  async createUser(userInfo: UserInfo) {
    const keys = ['id', 'name'];
    // tslint:disable-next-line:no-any
    const values: any[] = [userInfo.id, userInfo.name].map(SqlString.escape);

    if (userInfo.email) {
      keys.push('email');
      values.push(SqlString.escape(userInfo.email.toLowerCase()));
    }

    if (userInfo.phone) {
      keys.push('phone');
      values.push(userInfo.phone);
    }

    if (userInfo.password) {
      keys.push('secret');
      const hashed = await bcrypt.hash(userInfo.password, SALT_ROUNDS);
      values.push(SqlString.escape(hashed));
    }

    const keyStr = keys.join(',');
    const valuesStr = values.join(',');
    const query = `INSERT INTO identities (${keyStr}) VALUES (${valuesStr})`;
    debug('createUser', query);
    return this.db.runAsync(query).catch((e: Error) => {
      errors('CREATE USER', e.message);
      if (
        e.message ===
        'SQLITE_CONSTRAINT: UNIQUE constraint failed: identities.id'
      ) {
        throw new SIMPLE_AUTH_ERRORS.DuplicateId(userInfo.id.toString());
      } else if (
        e.message ===
        'SQLITE_CONSTRAINT: UNIQUE constraint failed: identities.name'
      ) {
        throw new SIMPLE_AUTH_ERRORS.DuplicateUser(userInfo.name);
      } else {
        throw e;
      }
    });
  }

  async deliverPasswordReset(userInfo: UserInfo, newPassword: string) {
    throw new Error(
      'deliverPasswordReset not implemented/configured.\n' +
        'monkey punch this SimpleAuth with async deliverPasswordReset(UserInfo, string) method'
    );
  }

  /** Read a file contents as a string until we update to Node v10+. */
  fileToString(fileName: string): Promise<string> {
    return new Promise((resolve, reject) => {
      fs.readFile(fileName, (err, data) => {
        if (err) reject(err);
        resolve(data.toString());
      });
    });
  }

  async getPrivateKey(): Promise<string> {
    if (!this.privateKey) {
      this.privateKey = await this.fileToString(this.privateKeyFileName);
    }
    return this.privateKey;
  }

  async getPublicKey(): Promise<string> {
    if (!this.publicKey) {
      this.publicKey = await this.fileToString(this.publicKeyFileName);
    }
    return this.publicKey;
  }

  async getUser(id: number | string): Promise<UserInfo> {
    let query: string;
    if (typeof id === 'number') {
      query = `SELECT * FROM identities WHERE id=${id}`;
    } else {
      if (!id.match(/^\d+/)) {
        throw new TypeError(
          `getUser: id must be natural number, received '${id}'`
        );
      }
      query = `SELECT * FROM identities WHERE id=${id}`;
    }
    debug('getUser', query);
    const user = await this.db.getAsync(query);
    if (user && user.id) {
      user.id = user.id.toString();
    }
    return user;
  }

  async getUserByEmail(email: string): Promise<UserInfo> {
    const query = `SELECT * FROM identities WHERE email=${SqlString.escape(
      email.trim().toLowerCase()
    )}`;
    debug('getUserByEmail', query);
    const user = await this.db.getAsync(query);
    if (user && user.id) {
      user.id = user.id.toString();
    }
    return user;
  }

  async getUserByName(name: string): Promise<UserInfo> {
    const query = `SELECT * FROM identities WHERE name=${SqlString.escape(
      name.trim()
    )}`;
    debug('getUserByName', query);
    const user = await this.db.getAsync(query);
    if (user && user.id) {
      user.id = user.id.toString();
    }
    return user;
  }

  async resetPassword(userId: UserInfo) {
    let validatedId: UserInfo = {
      id: '',
      name: '',
    };
    if (userId.id) {
      validatedId = await this.getUser(userId.id);
    } else if (userId.email) {
      validatedId = await this.getUserByEmail(userId.email);
    } else if (userId.name) {
      validatedId = await this.getUserByName(userId.name);
    }

    if (!validatedId || !validatedId.id) {
      errors(`cannot reset password for ${userId}`);
      return '';
    }

    const tempPassword = crypto
      .randomBytes(TEMP_PASSWORD_LENGTH)
      .toString('ascii');

    const now = new Date().getTime();
    const exp = (now + SESSION_EXPIRY_MS) / 1000;
    const hashed = await bcrypt.hash(tempPassword, SALT_ROUNDS);
    const query =
      'UPDATE identities SET ' +
      `recovery=${SqlString.escape(hashed)}, ` +
      `recoveryExpiry=${exp} ` +
      `WHERE id=${validatedId.id}`;
    debug('resetPassword', query);
    await this.db.runAsync(query);

    await this.deliverPasswordReset(userId, tempPassword);
    return tempPassword;
  }

  async setPassword(userId: number, password: string) {
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const query = `UPDATE identities SET secret=${SqlString.escape(
      hashed
    )} WHERE id=${userId}`;
    debug('setPassword', query);
    return this.db.runAsync(query);
  }

  async setup() {
    const sa = this;
    return new Promise((resolve, reject) => {
      sa.db = (new sqlite3.Database(
        sa.sqliteFile,
        sqlite3.OPEN_CREATE | sqlite3.OPEN_READWRITE,
        // tslint:disable-next-line:no-any
        (err: any) => {
          if (err) {
            errors('sqlite open', err);
            reject(err);
          } else {
            debug('sqlite opened', sa.sqliteFile);
            resolve(this);
          }
        }
      ) as unknown) as sqlite3.Database;
    }).then(() => {
      return [
        'CREATE TABLE IF NOT EXISTS identities (' +
          'id INT NOT NULL UNIQUE, name TEXT NOT NULL UNIQUE, email TEXT, phone INT, ' +
          'secret TEXT, recovery TEXT, recoveryExpiry INT DEFAULT 0)',
        'CREATE INDEX IF NOT EXISTS identities_by_id ON identities(id)',
        'CREATE INDEX IF NOT EXISTS identities_by_name ON identities(name)',
        'CREATE INDEX IF NOT EXISTS identities_by_id ON identities(id)',
      ].reduce((accum: Promise<unknown>, query: string) => {
        debug('setup', query);
        return accum.then(() => sa.db.runAsync(query));
      }, Promise.resolve());
    });
  }

  /**
   * Create or refresh a session for a user.
   */
  async updateSession(userId: number, email: string): Promise<Session> {
    debug('updateSession', userId, email);
    const now = new Date().getTime();
    const exp = (now + SESSION_EXPIRY_MS) / 1000; // jwt uses epoch seconds
    const token = { exp, userId, email };
    const privateKey = await this.getPrivateKey();
    const signOpts = {
      algorithm: SIGN_ALGORITHM,
      audience: email || '',
    };
    return {
      email,
      id: userId.toString(),
      session: jwt.sign(token, privateKey, signOpts),
    };
  }

  // tslint:disable-next-line:no-any
  validateSessionPayload(session: Session, payload: any): boolean {
    debug('validate', session, payload);
    if (session.email && payload.email && session.email !== payload.email) {
      return false;
    }
    if (payload.userId && session.id.toString() !== payload.userId.toString()) {
      return false;
    }
    return true;
  }
}
