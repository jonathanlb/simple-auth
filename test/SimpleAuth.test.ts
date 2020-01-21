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

async function createSimpleAuth(): Promise<SimpleAuth> {
  const config = {
    dbFileName: ':memory:',
    privateKeyFileName: 'test/jwtRS256.key',
    publicKeyFileName: 'test/jwtRS256.key.pub',
  };
  const auth = new SimpleAuth(config);
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

  test('Sets a user password', async () => {
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

  test('Resets a user password by id', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);

    alice.email = '';
    let newPassword = '';
    const oldPassword = alice.password;
    auth.deliverPasswordReset = async (id: UserInfo, p: string) => {
      newPassword = p;
    };
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
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);

    alice.id = '';
    alice.name = '';
    let newPassword = '';
    const oldPassword = alice.password;
    auth.deliverPasswordReset = async (id: UserInfo, p: string) => {
      newPassword = p;
    };
    await auth.resetPassword(alice);
    expect(newPassword).not.toEqual('');

    return auth.close();
  });

  test('Resets a user password by name', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);

    alice.id = '';
    alice.email = '';
    let newPassword = '';
    const oldPassword = alice.password;
    auth.deliverPasswordReset = async (id: UserInfo, p: string) => {
      newPassword = p;
    };
    await auth.resetPassword(alice);
    expect(newPassword).not.toEqual('');

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

  test('Checks for password delivery override', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);

    let error;
    try {
      await auth.resetPassword(alice);
    } catch (e) {
      error = e;
    }
    expect(error.message).toEqual(
      expect.stringMatching(/deliverPasswordReset not implemented/)
    );
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
