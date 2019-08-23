import bcrypt = require('bcrypt');
import bluebird = require('bluebird');
import crypto = require('crypto');
import Debug = require('debug');
import sqlite3 = require('sqlite3');
import SqlString = require('sqlstring');

import {
  Authorizer,
  Credentials,
  Database,
  Session,
  SimpleAuthConfig,
  UserInfo,
} from './types';

sqlite3.Database.prototype = bluebird.promisifyAll(sqlite3.Database.prototype);

const SALT_ROUNDS = 10;
const SESSION_BYTES = 20;
const SESSION_EXPIRY_MS = 86400000; // 24 hours

const debug = Debug('SimpleAuth');
const errors = Debug('SimpleAuth:error');

const sqlite3F = sqlite3.verbose();

const INVALID_SESSION: Session = {
  id: -1,
  session: '',
};

function invalidSession() {
  return Object.assign({}, INVALID_SESSION);
}

export class SimpleAuth implements Authorizer {
  db: Database;
  sqliteFile: string;

  constructor(config: SimpleAuthConfig) {
    this.sqliteFile = config.file;
    this.db = {} as Database;
  }

  async authenticateSession(sessionObj: Session) {
    const { id, session } = sessionObj;
    if (!id || !session) {
      return Promise.resolve(false);
    }

    const now = new Date().getTime();
    const query = `SELECT session FROM identities WHERE id=${id} AND sessionExpiry>=${now}`;
    debug('authenticatSession', query);
    // tslint:disable-next-line:no-any
    const result = (await this.db.getAsync(query)) as any;
    return Promise.resolve(result && result.session === session);
  }

  async authenticateUser(credentials: Credentials): Promise<Session> {
    debug('authenticateUser', credentials);
    let query: string;
    if (credentials.id) {
      query = `SELECT id, secret FROM identities WHERE id=${credentials.id}`;
    } else if (credentials.name) {
      query = `SELECT id, secret FROM identities WHERE name=${SqlString.escape(
        credentials.name
      )}`;
    } else if (credentials.email) {
      query = `SELECT id, secret FROM identities WHERE email=${SqlString.escape(
        credentials.email
      )}`;
    } else {
      return Promise.resolve(invalidSession());
    }

    debug(query);
    // tslint:disable-next-line:no-any
    const user = (await this.db.getAsync(query)) as any;
    if (
      !user ||
      !user.secret ||
      !(await bcrypt.compare(credentials.password, user.secret))
    ) {
      return Promise.resolve(invalidSession());
    }

    return this.updateSession(user.id);
  }

  async close() {
    await this.db.close();
    debug('close');
    this.db = {} as Database;
    return;
  }

  async closeSession(userId: number) {
    const query = `UPDATE identities SET session=NULL, sessionExpiry=0 WHERE id=${userId}`;
    debug('closeSession', query);
    return this.db.runAsync(query);
  }

  async createUser(userInfo: UserInfo) {
    const keys = ['id', 'name'];
    const values = [userInfo.id, SqlString.escape(userInfo.name)];

    if (userInfo.email) {
      keys.push('email');
      values.push(SqlString.escape(userInfo.email));
    }

    if (userInfo.phone) {
      keys.push('phone');
      values.push(userInfo.phone);
    }

    if (userInfo.secret) {
      keys.push('secret');
      const hashed = await bcrypt.hash(userInfo.secret, SALT_ROUNDS);
      values.push(SqlString.escape(hashed));
    }

    const keyStr = keys.join(',');
    const valuesStr = values.join(',');
    const query = `INSERT INTO identities (${keyStr}) VALUES (${valuesStr})`;
    debug('createUser', query);
    return this.db.runAsync(query);
  }

  async getUser(id: number): Promise<UserInfo> {
    const query = `SELECT * FROM identities WHERE id=${id}`;
    debug('createUser', query);
    return this.db.getAsync(query) as Promise<UserInfo>;
  }

  async setPassword(userId: number, password: string) {
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const query = `UPDATE identities SET password=${hashed} WHERE id=${userId}`;
    debug('setPassword', query);
    return this.db.runAsync(query);
  }

  async setup() {
    const sa = this;
    return new Promise((resolve, reject) => {
      sa.db = (new sqlite3F.Database(
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
      ) as unknown) as Database;
    }).then(() => {
      return [
        'CREATE TABLE IF NOT EXISTS identities (' +
          'id INT NOT NULL UNIQUE, name TEXT NOT NULL UNIQUE, email TEXT, phone INT, ' +
          'secret TEXT, recovery TEXT, recoveryExpiry INT DEFAULT 0, ' +
          'session TEXT, sessionExpiry INT DEFAULT 0)',
        'CREATE INDEX IF NOT EXISTS identities_by_id ON identities(id)',
        'CREATE INDEX IF NOT EXISTS identities_by_name ON identities(name)',
        'CREATE INDEX IF NOT EXISTS identities_by_id ON identities(id)',
      ].reduce((accum: Promise<unknown>, query: string) => {
        debug('setup', query);
        return accum.then(() => sa.db.runAsync(query));
      }, Promise.resolve(true));
    });
  }

  async updateSession(userId: number): Promise<Session> {
    const db = this.db;
    const now = new Date().getTime();
    const newExpiry = now + SESSION_EXPIRY_MS;
    const newSession = crypto.randomBytes(SESSION_BYTES).toString('hex');

    let query =
      `UPDATE identities SET session=${SqlString.escape(newSession)} ` +
      `WHERE id=${userId} AND sessionExpiry<=${now}`;
    debug('serialize update', query);
    await db.runAsync(query);

    query = `UPDATE identities SET sessionExpiry=${newExpiry} WHERE id=${userId}`;
    debug('serialize update', query);
    await db.runAsync(query);

    query = `SELECT id, session FROM identities WHERE id=${userId}`;
    debug('serialize update', query);
    return db.getAsync(query) as Promise<Session>;
  }
}
