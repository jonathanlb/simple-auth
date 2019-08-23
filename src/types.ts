export interface Authorizer {
  authenticateSession: (session: Session) => Promise<unknown>;
  authenticateUser: (credentials: Credentials) => Promise<Session>;
  close: () => Promise<unknown>;
  setup: () => Promise<unknown>;
}

export interface Credentials {
  email?: number;
  id?: number;
  name?: string;
  password: string;
}

// types for bluebird/sqlite3 operations
export interface Database {
  close: () => Promise<unknown>;
  getAsync: (sql: string) => Promise<unknown>;
  runAsync: (sql: string) => Promise<unknown>;
}

export interface Session {
  id: number;
  session: string;
}

export interface SimpleAuthConfig {
  file: string;
}

// TODO expose only general errors
export const SIMPLE_AUTH_ERRORS = {
  DuplicateId: new Error(
    'SQLITE_CONSTRAINT: UNIQUE constraint failed: identities.id'
  ),
  DuplicateUser: new Error(
    'SQLITE_CONSTRAINT: UNIQUE constraint failed: identities.name'
  ),
};

export interface UserInfo {
  id: number;
  name: string;
  email?: string;
  phone?: number;
  secret?: string;
}
