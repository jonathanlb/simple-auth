import Debug = require('debug');

import { SimpleAuth, SimpleAuthConfig } from '../src';
import { Credentials, SIMPLE_AUTH_ERRORS, UserInfo } from '../src/types';

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
describe('SimpleAuth', () => {
  test('Initializes', async () => {
    const auth = await createSimpleAuth();
    await auth.close();
  });

  test('Creates a user', async () => {
    const auth = await createSimpleAuth();
    const info = aliceInfo();
    await auth.createUser(info);
    const storedInfo = await auth.getUser(info.id);
    expect(storedInfo.id).toBe(info.id);
    expect(storedInfo.name).toEqual(info.name);
    expect(storedInfo.email).toEqual(info.email);
    await auth.close();
  });

  test('Rejects duplicate user ids', async () => {
    const auth = await createSimpleAuth();
    await auth.createUser(aliceInfo());
    expect(
      auth.createUser(aliceInfo({ name: 'Bob', email: 'bob@example.com' }))
    ).rejects.toThrow(SIMPLE_AUTH_ERRORS.DuplicateId);
  });

  test('Rejects duplicate user names', async () => {
    const auth = await createSimpleAuth();
    await auth.createUser(aliceInfo());
    expect(
      auth.createUser(aliceInfo({ id: '91', email: 'alice@aol.com' }))
    ).rejects.toThrow(SIMPLE_AUTH_ERRORS.DuplicateUser);
  });

  test('Authorizes a user', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const result = await auth.authenticateUser({
      email: alice.email,
      password: alice.password as string,
    });
    expect(result.session).toBeTruthy();
    expect(result.id).toEqual(alice.id);
    await auth.close();
  });

  test('Denies a user', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const result = await auth.authenticateUser({
      email: alice.email,
      password: '?' as string,
    });
    expect(result.session).not.toBeTruthy();
    await auth.close();
  });

  test('Denies a non-user', async () => {
    const auth = await createSimpleAuth();
    const result = await auth.authenticateUser({
      id: '1',
      email: 'alice@gmail.com',
      password: 'letMeIn' as string,
    });
    expect(result.session).not.toBeTruthy();
    await auth.close();
  });

  test('Denies non-credentials', async () => {
    const auth = await createSimpleAuth();
    const result = await auth.authenticateUser(aliceInfo() as Credentials);
    expect(result.session).not.toBeTruthy();
    await auth.close();
  });

  test('Authorizes a session', async () => {
    const auth = await createSimpleAuth();
    const alice = aliceInfo();
    await auth.createUser(alice);
    const session = await auth.authenticateUser({
      email: alice.email,
      password: alice.password as string,
    });
    const result = await auth.authenticateSession(session);
    expect(result).toBeTruthy();
    await auth.close();
  });

  test('Denies a session', async () => {
    const auth = await createSimpleAuth();
    const result = await auth.authenticateSession({
      id: '17',
      session: 'hello',
    });
    debug('deny session', result);
    expect(result).not.toBeTruthy();
    await auth.close();
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
    expect(session.id).toEqual(alice.id);
    await auth.close();
  });
});
