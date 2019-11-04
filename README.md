# SimpleAuth
SimpleAuth is a [sqlite-based](https://www.npmjs.com/package/sqlite3)
user-authentication package.
Users can authenticate with a password that is checked against the 
password hash stored at the server.
Upon success, the user receives a token that can be used in leiu of
the password and database access for a period of time (24 hours by default).

## Password Recovery
Users can reset their passwords via request using their id, name, or email.
Upon request, the server will deliver a new password by invoking
the `SimpleAuth.deliverPasswordReset(userId: number, passwd: string)` method,
whose implementation must be supplied by the installation.

We suggest using [nodemailer](https://www.npmjs.com/package/nodemailer) to
deliver.
