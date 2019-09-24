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

export interface Session {
  id: number;
  session: string;
}

export interface SimpleAuthConfig {
  file: string;
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
  NotAuthorizedException: class extends Error {
    constructor(msg: string) {
      super(msg);
    }
  },
};

export interface UserInfo {
  id: number;
  name: string;
  email?: string;
  phone?: number;
  secret?: string;
}
