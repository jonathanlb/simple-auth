// Reset a user password.
// Example:
// npm run compile
// DEBUG='admin' node build/src/admin/resetUserPassword.js data/mydb.sqlite3 \
//   'Jonathan Bredin' 'secret stuff'

import bcrypt = require('bcrypt');
import Debug = require('debug');
import sqlite3 = require('sqlite3-promise');

const debug = Debug('admin');

if (process.argv.length < 4) {
  // eslint-disable-next-line
  console.error('USAGE: <db-file> <user-name> <new-password>');
  process.exit(2);
}
const dbFile = process.argv[2];
const userName = process.argv[3];
const newPassword = process.argv[4];

const saltRounds = 10;

debug('opening db', dbFile);
const db = new sqlite3.Database(dbFile, sqlite3.OPEN_READWRITE, err => {
  if (err) {
    console.error(`cannot open db at ${dbFile}: ${err.message}`); // eslint-disable-line
    process.exit(1);
  }
  debug('open OK', err);
});

debug('hashing for', userName);
bcrypt.hash(newPassword, saltRounds).then(async hash => {
  let query = `SELECT rowid, name FROM identities WHERE name LIKE '%${userName}%'`;
  debug('userId', query);
  const userIdResult = await db.allAsync(query);
  if (!userIdResult || userIdResult.length !== 1) {
    // eslint-disable-next-line no-throw-literal
    throw new Error(
      `Invalid/non-unique user name ${userName} : ${userIdResult.map(
        x => x.name
      )}`
    );
  }
  debug('userId', userIdResult);
  const userId = userIdResult[0].rowid;

  query =
    `UPDATE identities SET secret='${hash}', recovery=NULL ` +
    `WHERE rowid=${userId}`;
  debug('update', query);
  const result = await db.allAsync(query);
  debug('OK', result);
});
