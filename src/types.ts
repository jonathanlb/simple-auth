export interface Authorizer {
  authenticateSession: (session: Session) => Promise<unknown>;
  authenticateUser: (credentials: Credentials) => Promise<Session>;
  close: () => Promise<unknown>;
  setup: () => Promise<unknown>;
}

export interface Credentials {
  email?: string;
  id?: string;
  name?: string;
  password: string;
  phoneNumber?: number;
}

export interface DecodedSession {
  aud?: string;
  email?: string;
  exp: number;
  iat: number;
  userId: string;
}

export interface Session extends DecodedSession {
  session: string;
}

export interface SimpleAuthConfig {
  dbFileName: string;
  privateKeyFileName: string;
  publicKeyFileName: string;
}

export const SIMPLE_AUTH_ERRORS = {
  DuplicateId: class extends Error {
    constructor(id: string) {
      super(`Unique constraint failed: credentials id '${id}'`);
    }
  },
  DuplicateUser: class extends Error {
    constructor(userName: string) {
      super(`Unique constraint failed: credentials name '${userName}'`);
    }
  },
  ExpiredSession: class extends Error {
    constructor(expMillis: number) {
      super(`Session expired at ${expMillis}`);
    }
  },
  NotAuthorizedException: class extends Error {
    constructor(msg: string) {
      super(msg);
    }
  },
};

export interface UserInfo {
  id: string;
  name: string;
  email?: string;
  phone?: number;
  password?: string;
}
