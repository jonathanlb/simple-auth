import Debug = require('debug');

import { SimpleAuth, SimpleAuthConfig } from '../src';
import {
  Credentials,
  DecodedSession,
  SIMPLE_AUTH_ERRORS,
  UserInfo,
} from '../src/types';

const debug = Debug('SimpleAuth:test');

// tslint:disable-next-line:no-any
function aliceInfo(overrides: any = {}): UserInfo {
  return Object.assign(
    {
      email: 'alice@example.com',
      id: '88',
      name: 'Alice',
      password: 's3cret',
    },
    overrides
  );
}

// tslint:disable-next-line:no-any
function bobInfo(overrides: any = {}): UserInfo {
  return Object.assign(
    {
      email: 'bob@example.com',
      id: '89',
      name: 'Bob',
      password: 'hUsh',
    },
    overrides
  );
}

// tslint:disable-next-line:no-any
async function createSimpleAuth(otherOpts?: any): Promise<SimpleAuth> {
  const config = {
    dbFileName: ':memory:',
    privateKeyFileName: 'test/jwtRS256.key',
    publicKeyFileName: 'test/jwtRS256.key.pub',
  };
  const auth = new SimpleAuth(
    Object.assign(config, otherOpts) as SimpleAuthConfig
  );
  await auth.setup();
  return auth;
}

// Tests require public and private keys.
//
// ssh-keygen -t rsa -b 1024 -m PEM -f jwtRS256.key
// # Don't add passphrase
// openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
//
describe('Maintain', () => {
  test('Creates a user', async () => {
    const auth = await createSimpleAuth();
    const info = aliceInfo();
    await auth.createUser(info);
    const storedInfo = await auth.getUser(info.id);
    expect(storedInfo.id).toBe(info.id);
    expect(storedInfo.name).toEqual(info.name);
    expect(storedInfo.email).toEqual(info.email);
    return auth.close();
  });

  test('Deletes a user', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    // tslint:disable-next-line
    await auth.deleteUser(parseInt(alice.id, 10));
    const result = await auth.authenticateUser({
      name: alice.name,
      password: alice.password as string,
    });
    expect(result.session).not.toBeTruthy();
    return auth.close();
  });

  test('Sets a user password with string id', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);

    const newPassword = alice.password + 'XXX';
    // tslint:disable-next-line
    await auth.setPassword(parseInt(alice.id, 10), newPassword);
    let result = await auth.authenticateUser({
      name: alice.name,
      password: newPassword,
    });
    expect(result.session).toBeTruthy();

    result = await auth.authenticateUser({
      name: alice.name,
      password: newPassword + '___',
    });
    expect(result.session).not.toBeTruthy();

    return auth.close();
  });

  test('Sets a user password with number id', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);

    const newPassword = alice.password + 'XXX';
    await auth.setPassword(alice.id, newPassword);
    let result = await auth.authenticateUser({
      name: alice.name,
      password: newPassword,
    });
    expect(result.session).toBeTruthy();

    result = await auth.authenticateUser({
      name: alice.name,
      password: newPassword + '___',
    });
    expect(result.session).not.toBeTruthy();

    return auth.close();
  });

  test('Sets a user password with user info', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);

    const newPassword = alice.password + 'XXX';
    await auth.setPassword(alice, newPassword);
    let result = await auth.authenticateUser({
      name: alice.name,
      password: newPassword,
    });
    expect(result.session).toBeTruthy();

    result = await auth.authenticateUser({
      name: alice.name,
      password: newPassword + '___',
    });
    expect(result.session).not.toBeTruthy();

    return auth.close();
  });

  test('Reset password fails fast if not configured', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    let message = '';
    await auth.resetPassword(alice).catch(e => {
      message = e.message;
    });
    expect(message).toEqual(
      expect.stringContaining('deliverPasswordReset not implemented')
    );
  });

  test('Resets a user password by id', async () => {
    let newPassword = '';
    const auth = await createSimpleAuth({
      deliverPasswordReset: async (id: UserInfo, p: string) => {
        newPassword = p;
      },
    });
    const alice = aliceInfo();
    await auth.createUser(alice);

    alice.email = '';
    const oldPassword = alice.password;
    await auth.resetPassword(alice);
    expect(newPassword).not.toEqual('');

    let result = await auth.authenticateUser({
      name: alice.name,
      password: newPassword,
    });
    expect(result.session).toBeTruthy();

    result = await auth.authenticateUser({
      name: alice.name,
      password: newPassword + '___',
    });
    expect(result.session).not.toBeTruthy();

    // Old password is invalid until once user resets it.
    result = await auth.authenticateUser({
      name: alice.name,
      password: oldPassword as string,
    });
    expect(result.session).not.toBeTruthy();

    return auth.close();
  });

  test('Resets a user password by email', async () => {
    let newPassword = '';
    const auth = await createSimpleAuth({
      deliverPasswordReset: async (id: UserInfo, p: string) => {
        newPassword = p;
      },
    });
    const alice = aliceInfo();
    await auth.createUser(alice);

    alice.id = '';
    alice.name = '';
    const oldPassword = alice.password;
    await auth.resetPassword(alice);
    expect(newPassword).not.toEqual('');

    return auth.close();
  });

  test('Resets a user password by name', async () => {
    let newPassword = '';
    const auth = await createSimpleAuth({
      deliverPasswordReset: async (id: UserInfo, p: string) => {
        newPassword = p;
      },
    });

    const alice = aliceInfo();
    await auth.createUser(alice);

    alice.id = '';
    alice.email = '';
    await auth.resetPassword(alice);
    expect(newPassword).not.toEqual('');

    return auth.close();
  });

  test('Resets a user password to known value', async () => {
    let deliveredPassword = '';
    const auth = await createSimpleAuth({
      deliverPasswordReset: async (id: UserInfo, p: string) => {
        deliveredPassword = p;
      },
    });

    const alice = aliceInfo();
    await auth.createUser(alice);

    alice.id = '';
    alice.email = '';
    const newPassword = 'reset!';
    await auth.resetPassword(alice, newPassword);
    expect(deliveredPassword).toEqual(newPassword);

    return auth.close();
  });

  test('Fails to set a non-user password', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();

    const newPassword = alice.password + 'XXX';
    let message = '';
    try {
      await auth.setPassword(alice, newPassword);
    } catch (e) {
      message = e.message;
    }
    expect(message).toEqual(expect.stringMatching(/cannot set password for/));

    return auth.close();
  });

  test('Silently fails to reset password for unknown user', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();

    let newPassword = '';
    auth.deliverPasswordReset = async (id: UserInfo, p: string) => {
      newPassword = p;
    };
    const result = await auth.resetPassword(alice);
    expect(newPassword).toEqual('');
    expect(result).toEqual('');

    return auth.close();
  });

  test('Validates email by prefix', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const userId = { email: 'alice' } as UserInfo;
    const validatedId = (await auth.validateId(
      userId,
      'beginsWith'
    )) as UserInfo;
    expect(validatedId.id).toBeDefined();
    return auth.close();
  });

  test('Validates email by substring', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const userId = { email: '@' } as UserInfo;
    const validatedId = (await auth.validateId(userId, 'contains')) as UserInfo;
    expect(validatedId.id).toBeDefined();
    return auth.close();
  });

  test('Validates email by suffix', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const userId = { email: '.com' } as UserInfo;
    const validatedId = (await auth.validateId(userId, 'endsWith')) as UserInfo;
    expect(validatedId.id).toBeDefined();
    return auth.close();
  });

  test('Handles erroneous multiple email validation', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const bob = bobInfo();
    await auth.createUser(bob);
    const userId = { email: '@' } as UserInfo;
    const validatedId = (await auth.validateId(userId, 'contains')) as UserInfo;
    expect(validatedId).toBeUndefined();
    return auth.close();
  });

  test('Validates name by prefix', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const userId = { name: 'A' } as UserInfo;
    const validatedId = (await auth.validateId(
      userId,
      'beginsWith'
    )) as UserInfo;
    expect(validatedId.id).toBeDefined();
    return auth.close();
  });

  test('Validates name by substring', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const userId = { name: 'li' } as UserInfo;
    const validatedId = (await auth.validateId(userId, 'contains')) as UserInfo;
    expect(validatedId.id).toBeDefined();
    return auth.close();
  });

  test('Validates name by suffix', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const userId = { name: 'e' } as UserInfo;
    const validatedId = (await auth.validateId(userId, 'endsWith')) as UserInfo;
    expect(validatedId.id).toBeDefined();
    return auth.close();
  });
});

describe('Operation', () => {
  test('Initializes', async () => {
    const auth = await createSimpleAuth();
    return auth.close();
  });

  test('Gets user by numeric id', async () => {
    const auth = await createSimpleAuth();
    const info = aliceInfo();
    await auth.createUser(info);
    // tslint:disable-next-line
    const storedInfo = await auth.getUser(parseInt(info.id, 10));
    expect(storedInfo.name).toEqual(info.name);
    expect(storedInfo.email).toEqual(info.email);
    return auth.close();
  });

  test('Expects numerical id', async () => {
    const auth = await createSimpleAuth();
    const info = aliceInfo();
    await auth.createUser(info);
    expect(auth.getUser('one')).rejects.toThrow(TypeError);
    return auth.close();
  });

  test('Rejects duplicate user ids', async () => {
    const auth = await createSimpleAuth();
    let userInfo = aliceInfo();
    await auth.createUser(userInfo);

    userInfo = aliceInfo({
      name: 'Bob',
      email: 'bob@example.com',
      phone: 1235551212,
    });
    let error;
    try {
      await auth.createUser(userInfo);
    } catch (e) {
      error = e;
    }
    expect(error).toEqual(new SIMPLE_AUTH_ERRORS.DuplicateId(userInfo.id));
    return auth.close();
  });

  test('Rejects duplicate user names', async () => {
    const auth = await createSimpleAuth();
    let userInfo = aliceInfo();
    await auth.createUser(userInfo);

    userInfo = aliceInfo({ id: '91', email: 'alice@aol.com' });
    let error;
    try {
      await auth.createUser(userInfo);
    } catch (e) {
      error = e;
    }
    expect(error).toEqual(new SIMPLE_AUTH_ERRORS.DuplicateUser(userInfo.name));
    return auth.close();
  });

  test('Authorizes a user by email', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const result = await auth.authenticateUser({
      email: alice.email,
      password: alice.password as string,
    });
    expect(result.session).toBeTruthy();
    expect(result.userId).toEqual(alice.id);
    return auth.close();
  });

  test('Authorizes a user by name', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const result = await auth.authenticateUser({
      name: alice.name,
      password: alice.password as string,
    });
    expect(result.session).toBeTruthy();
    expect(result.userId).toEqual(alice.id);
    return auth.close();
  });

  test('Denies a user by email', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const result = await auth.authenticateUser({
      email: alice.email,
      password: '?' as string,
    });
    expect(result.session).not.toBeTruthy();
    return auth.close();
  });

  test('Denies a user by name', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const result = await auth.authenticateUser({
      name: alice.name,
      password: '?' as string,
    });
    expect(result.session).not.toBeTruthy();
    return auth.close();
  });

  test('Denies a non-user', async () => {
    const auth = await createSimpleAuth();
    const result = await auth.authenticateUser({
      id: '1',
      email: 'alice@gmail.com',
      password: 'letMeIn' as string,
    });
    expect(result.session).not.toBeTruthy();
    return auth.close();
  });

  test('Denies non-credentials', async () => {
    const auth = await createSimpleAuth();
    const result = await auth.authenticateUser(aliceInfo() as Credentials);
    expect(result.session).not.toBeTruthy();
    return auth.close();
  });

  test('Denies empty credentials', async () => {
    const auth = await createSimpleAuth();
    const result = await auth.authenticateUser({} as Credentials);
    expect(result.session).not.toBeTruthy();
    return auth.close();
  });

  test('Denies corrupt credential email', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const session = await auth.authenticateUser({
      name: alice.name,
      password: alice.password as string,
    });
    session.email += 'xxx';
    const result = await auth.authenticateSession(session);
    expect(result).not.toBeTruthy();
    return auth.close();
  });

  test('Denies corrupt credential id', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const session = await auth.authenticateUser({
      name: alice.name,
      password: alice.password as string,
    });
    session.userId += '1';
    const result = await auth.authenticateSession(session);
    expect(result).not.toBeTruthy();
    return auth.close();
  });

  test('Authorizes a session', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const session = await auth.authenticateUser({
      email: alice.email,
      password: alice.password as string,
    });
    const result = (await auth.authenticateSession(session)) as DecodedSession;
    const nowS = new Date().getTime() / 1000;
    expect(result).toBeTruthy();
    expect(result.exp).toBeGreaterThanOrEqual(nowS);
    expect(result.iat).toBeGreaterThan(0);
    expect(result.iat).toBeLessThanOrEqual(nowS);
    expect(result.aud).toEqual(alice.email);
    expect(result.email).toEqual(alice.email);
    expect(result.userId).toEqual(alice.id);
    return auth.close();
  });

  test('Denies a session', async () => {
    const auth = await createSimpleAuth();
    const nowS = new Date().getTime() / 1000;
    const result = await auth.authenticateSession({
      exp: nowS + 360,
      iat: nowS,
      userId: '17',
      session: 'hello',
    });
    debug('deny session', result);
    expect(result).not.toBeTruthy();
    return auth.close();
  });

  test('Updates a user password', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);

    const newPassword = `--${alice.password}--`;
    // tslint:disable-next-line
    await auth.setPassword(parseInt(alice.id, 10), newPassword);
    const session = await auth.authenticateUser({
      email: alice.email,
      password: newPassword,
    });
    expect(session.session).toBeTruthy();
    expect(session.userId).toEqual(alice.id);
    return auth.close();
  });

  test('Rejects expired session', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const session = await auth.updateSession(
      alice.id,
      alice.email as string,
      -10000
    );
    const result = await auth.authenticateSession(session);
    expect(result).not.toBeTruthy();
    return auth.close();
  });
});
