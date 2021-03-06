import bcrypt = require('bcrypt');
import Debug = require('debug');
import fs = require('fs');
import jwt = require('jsonwebtoken');
import sqlite3 = require('sqlite3-promise');
import SqlString = require('sqlstring');

import {
  Authorizer,
  Credentials,
  DecodedSession,
  SIMPLE_AUTH_ERRORS,
  Session,
  SimpleAuthConfig,
  UserInfo,
} from './types';

const SALT_ROUNDS = 10;
const SESSION_BYTES = 20;
const SESSION_EXPIRY_MS = 86400000; // 24 hours
const SIGN_ALGORITHM = 'RS256'; // for ssh-keygen -t rsa ... ; openssl rsa

const SEARCH_BEGINS_WITH = 'beginswith';
const SEARCH_CONTAINS = 'contains';
const SEARCH_ENDS_WITH = 'endswith';

const debug = Debug('SimpleAuth');
const errors = Debug('SimpleAuth:error');

const INVALID_SESSION: Session = {
  email: '',
  exp: 0,
  iat: 0,
  userId: '-1',
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
  deliverPasswordResetDefined: boolean;

  constructor(config: SimpleAuthConfig) {
    this.sqliteFile = config.dbFileName;
    this.db = {} as sqlite3.Database;
    this.privateKey = '';
    this.privateKeyFileName = config.privateKeyFileName;
    this.publicKey = '';
    this.publicKeyFileName = config.publicKeyFileName;
    if (config.deliverPasswordReset) {
      this.deliverPasswordResetDefined = true;
      this.deliverPasswordReset = config.deliverPasswordReset;
    } else {
      this.deliverPasswordResetDefined = false;
    }
  }

  async authenticateSession(
    sessionObj: Session
  ): Promise<DecodedSession | boolean> {
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

      return new Promise((resolve, reject) => {
        jwt.verify(session, publicKey, verifyOpts, (err, decoded) => {
          if (err) {
            errors('authenticateSession internal', err.message);
            resolve(false);
          }
          if (this.validateSessionPayload(sessionObj, decoded)) {
            resolve(decoded as DecodedSession);
          } else {
            resolve(false);
          }
        });
      });
    } catch (e) {
      errors('authenticateSession', e.message);
      return false;
    }
  }

  async authenticateUser(
    credentials: Credentials,
    sessionExpiryMillisOpt?: number
  ): Promise<Session> {
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

    if (
      user.secret &&
      (await bcrypt.compare(credentials.password, user.secret))
    ) {
      debug('password OK', user);
      return this.updateSession(user.id, user.email, sessionExpiryMillisOpt);
    }

    if (
      user.recovery &&
      (await bcrypt.compare(credentials.password, user.recovery))
    ) {
      debug('hint OK, resetting password', user);
      await this.setPassword(user.id, credentials.password);
      return this.updateSession(user.id, user.email, sessionExpiryMillisOpt);
    }

    debug('found user, invalid password/hint', user, credentials);
    return Promise.resolve(invalidSession());
  }

  async close() {
    this.db.close();
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

  async deleteUser(userId: number) {
    const query = `DELETE FROM identities WHERE id=${userId}`;
    debug('deleteUser', query);
    return this.db.runAsync(query);
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
        if (err) {
          reject(err);
        } else {
          resolve(data.toString());
        }
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

  async getUserByEmail(email: string, searchOpt?: string): Promise<UserInfo> {
    let emailLike;
    let query;
    const lowerCaseEmail = email.trim().toLowerCase();
    const search = (searchOpt || '').toLowerCase();

    if (!search) {
      query = `SELECT * FROM identities WHERE email=${SqlString.escape(
        lowerCaseEmail
      )}`;
    } else {
      switch (search) {
        case SEARCH_BEGINS_WITH:
          emailLike = `${lowerCaseEmail}%`;
          break;
        case SEARCH_CONTAINS:
          emailLike = `%${lowerCaseEmail}%`;
          break;
        case SEARCH_ENDS_WITH:
          emailLike = `%${lowerCaseEmail}`;
          break;
        default:
          emailLike = lowerCaseEmail;
      }
      query = `SELECT * FROM identities WHERE email LIKE ${SqlString.escape(
        emailLike
      )}`;
    }
    debug('getUserByEmail', query);
    const results = await this.db.allAsync(query);
    debug('result getUserByEmail', results);
    if (results && results.length === 1) {
      if (results[0].id) {
        results[0].id = results[0].id.toString();
      }
      return results[0];
    } else {
      results.length = 0;
      return results[0]; // undefined
    }
  }

  async getUserByName(name: string, searchOpt?: string): Promise<UserInfo> {
    const search = (searchOpt || '').toLowerCase();
    const nameTrim = name.trim();
    let query;

    if (!search) {
      query = `SELECT * FROM identities WHERE name=${SqlString.escape(
        nameTrim
      )}`;
    } else {
      let nameLike;
      switch (search) {
        case SEARCH_BEGINS_WITH:
          nameLike = `${nameTrim}%`;
          break;
        case SEARCH_CONTAINS:
          nameLike = `%${nameTrim}%`;
          break;
        case SEARCH_ENDS_WITH:
          nameLike = `%${nameTrim}`;
          break;
        default:
          nameLike = `${nameTrim}`;
      }
      query = `SELECT * FROM identities WHERE name LIKE ${SqlString.escape(
        nameLike
      )}`;
    }
    debug('getUserByName', query);
    const results = await this.db.allAsync(query);
    debug('results getUserByName', results);
    if (results && results.length === 1) {
      if (results[0].id) {
        results[0].id = results[0].id.toString();
      }
      return results[0];
    } else {
      results.length = 0;
      return results[0]; // undefined
    }
  }

  async resetPassword(
    userId: UserInfo,
    optPassword?: string,
    searchOpt?: string
  ) {
    debug('resetPassword', userId);
    if (!this.deliverPasswordResetDefined) {
      // call the stub throwing an error.
      await this.deliverPasswordReset({} as UserInfo, '');
    }
    const validatedId = await this.validateId(userId, searchOpt);
    if (!validatedId || !validatedId.id) {
      errors(`cannot reset password for ${userId}`);
      return '';
    }

    // https://gist.github.com/6174/6062387
    // Remove confusing 0/O and 1/l characters.
    const tempPassword =
      optPassword ||
      Math.random()
        .toString(36)
        .substring(2)
        .replace(/0/g, '_')
        .replace(/O/g, '-')
        .replace(/1/g, '+')
        .replace(/l/g, ':');

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

  async setPassword(id: number | string | UserInfo, password: string) {
    let userId = 0;
    if (typeof id === 'string') {
      // tslint:disable-next-line
      userId = parseInt(id, 10);
    } else if (typeof id === 'number') {
      userId = id;
    } else {
      const validatedId = await this.validateId(id);
      if (!validatedId) {
        throw new Error(`cannot set password for ${id}`);
      }
      // tslint:disable-next-line
      userId = parseInt((validatedId as UserInfo).id, 10);
    }

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
        'CREATE INDEX IF NOT EXISTS identities_by_email ON identities(email)',
      ].reduce((accum: Promise<unknown>, query: string) => {
        debug('setup', query);
        return accum.then(() => sa.db.runAsync(query));
      }, Promise.resolve());
    });
  }

  /**
   * Create or refresh a session for a user.
   */
  async updateSession(
    userId: number | string,
    email: string,
    sessionExpiryMillisOpt?: number
  ): Promise<Session> {
    debug('updateSession', userId, email, sessionExpiryMillisOpt);
    const sessionExpiryMillis = sessionExpiryMillisOpt || SESSION_EXPIRY_MS;
    const now = new Date().getTime();
    const exp = (now + sessionExpiryMillis) / 1000; // jwt uses epoch seconds
    const token = { exp, userId: userId.toString(), email };
    const privateKey = await this.getPrivateKey();
    const signOpts = {
      algorithm: SIGN_ALGORITHM,
      audience: email || '',
    };

    return new Promise((resolve, reject) => {
      jwt.sign(token, privateKey, signOpts, (err, session) => {
        if (err) {
          errors('updateSession', err.message);
          reject(err);
        }
        resolve({
          email,
          exp,
          iat: now / 1000,
          userId: userId.toString(),
          session,
        });
      });
    });
  }

  validateId(userId: UserInfo, searchOpt?: string): Promise<UserInfo | void> {
    if (userId.id) {
      return this.getUser(userId.id);
    } else if (userId.email) {
      return this.getUserByEmail(userId.email, searchOpt);
    } else if (userId.name) {
      return this.getUserByName(userId.name, searchOpt);
    } else {
      return Promise.resolve(undefined);
    }
  }

  // tslint:disable-next-line:no-any
  validateSessionPayload(session: Session, payload: any): boolean {
    debug('validate', session, payload);
    if (session.email && payload.email && session.email !== payload.email) {
      debug('email validation error');
      return false;
    }
    if (
      payload.userId &&
      session.userId.toString() !== payload.userId.toString()
    ) {
      debug('userId validation error');
      return false;
    }
    return true;
  }
}
