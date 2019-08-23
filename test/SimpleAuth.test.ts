import { SimpleAuth, SimpleAuthConfig } from '../src';
import { SIMPLE_AUTH_ERRORS } from '../src/types';

async function createSimpleAuth(): Promise<SimpleAuth> {
  const config = {
    file: ':memory:',
  };
  const auth = new SimpleAuth(config);
  await auth.setup();
  return auth;
}

describe('SimpleAuth', () => {
  test('Initializes', async () => {
    const auth = await createSimpleAuth();
    await auth.close();
  });

  test('Creates a user', async () => {
    const auth = await createSimpleAuth();
    const info = {
      id: 88,
      name: 'Alice',
      email: 'alice@example.com',
    };
    await auth.createUser(info);
    const storedInfo = await auth.getUser(info.id);
    expect(storedInfo.id).toBe(info.id);
    expect(storedInfo.name).toEqual(info.name);
    expect(storedInfo.email).toEqual(info.email);
    await auth.close();
  });

  test('Rejects duplicate user ids', async () => {
    const auth = await createSimpleAuth();
    await auth.createUser({ id: 89, name: 'Alice' });
    expect(auth.createUser({ id: 89, name: 'Bob' })).rejects.toThrow(
      SIMPLE_AUTH_ERRORS.DuplicateId
    );
    await auth.close();
  });

  test('Rejects duplicate user names', async () => {
    const auth = await createSimpleAuth();
    await auth.createUser({ id: 90, name: 'Alice' });
    expect(auth.createUser({ id: 91, name: 'Alice' })).rejects.toThrow(
      SIMPLE_AUTH_ERRORS.DuplicateUser
    );
    await auth.close();
  });

  test('Authorizes a user', async () => {
    const auth = await createSimpleAuth();
    await auth.createUser({ id: 89, name: 'Alice', secret: 'seecr3t' });
    const result = await auth.authenticateUser({
      name: 'Alice',
      password: 'seecr3t',
    });
    expect(result.session).toBeTruthy();
    expect(result.id).toBe(89);
    await auth.close();
  });

  test('Denies a user', async () => {
    const auth = await createSimpleAuth();
    await auth.createUser({
      id: 89,
      name: 'Alice',
      email: 'alice@gmail.com',
      secret: 'seecr3t',
    });
    const result = await auth.authenticateUser({
      name: 'alice@gmail.com',
      password: '?',
    });
    expect(result.session).not.toBeTruthy();
    await auth.close();
  });

  test('Denies a non-user', async () => {
    const auth = await createSimpleAuth();
    const result = await auth.authenticateUser({ id: 1, password: 'letMeIn' });
    expect(result.session).not.toBeTruthy();
    await auth.close();
  });

  test('Denies non-credentials', async () => {
    const auth = await createSimpleAuth();
    const result = await auth.authenticateUser({ password: 'letMeIn' });
    expect(result.session).not.toBeTruthy();
    await auth.close();
  });

  test('Sessions are short-term idempotent', async () => {
    const auth = await createSimpleAuth();
    await auth.createUser({ id: 89, name: 'Alice', secret: 'seecr3t' });
    const s0 = await auth.authenticateUser({
      name: 'Alice',
      password: 'seecr3t',
    });
    const s1 = await auth.authenticateUser({
      name: 'Alice',
      password: 'seecr3t',
    });
    expect(s1).toEqual(s0);
    await auth.close();
  });

  test('Authorizes a session', async () => {
    const auth = await createSimpleAuth();
    await auth.createUser({ id: 89, name: 'Alice', secret: 'seecr3t' });
    const session = await auth.authenticateUser({
      name: 'Alice',
      password: 'seecr3t',
    });
    const result = await auth.authenticateSession(session);
    expect(result).toBeTruthy();
    await auth.close();
  });

  test('Denies a session', async () => {
    const auth = await createSimpleAuth();
    const result = await auth.authenticateSession({ id: 17, session: 'hello' });
    expect(result).not.toBeTruthy();
    await auth.close();
  });

  test('Closes a session', async () => {
    const auth = await createSimpleAuth();
    await auth.createUser({ id: 89, name: 'Alice', secret: 'seecr3t' });
    const session = await auth.authenticateUser({
      name: 'Alice',
      password: 'seecr3t',
    });
    let result = await auth.authenticateSession(session);
    expect(result).toBeTruthy();

    await auth.closeSession(89);
    result = await auth.authenticateSession(session);
    expect(result).not.toBeTruthy();
    await auth.close();
  });
});
