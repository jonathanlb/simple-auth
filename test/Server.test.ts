import request = require('supertest');
import { Server } from '../src/Server';
import { SimpleAuth } from '../src/SimpleAuth';

const USER_INFO = {
  id: '1',
  email: 'who@there.com',
  name: 'Some User',
  password: 'secret',
};

// tslint:disable-next-line:no-any
async function createServer(startOpts: any = {}) {
  const auth = new SimpleAuth({
    dbFileName: ':memory:',
    privateKeyFileName: 'test/jwtRS256.key',
    publicKeyFileName: 'test/jwtRS256.key.pub',
  });
  const server = new Server(auth);
  const opts = Object.assign({ cookieExpiresMs: 60000, port: 0 }, startOpts);
  const router = await server.start(opts);
  await auth.createUser(USER_INFO);
  return { router, server };
}

describe('Server routing tests', () => {
  test('serves public key', async () => {
    const { server, router } = await createServer();
    const response = await request(router).get('/public-key');
    expect(response.status).toEqual(200);
    expect(response.text).toBeTruthy();

    expect(response.get('Set-Cookie')).toBeUndefined();
    expect(response.get('x-access-token')).toBeUndefined();
  });

  test('provides client ticket', async () => {
    const { server, router } = await createServer();
    const response = await request(router)
      .get(`/ticket-by-email/${USER_INFO.email}`)
      .set('x-access-token', USER_INFO.password);
    expect(response.status).toEqual(200);
    expect(response.text).toBeTruthy();

    const cookie = response.get('Set-Cookie');
    expect(cookie.length).toBe(1);
    expect(Server.extractTicket(cookie, 'ticket')).toBeTruthy();

    expect(response.get('x-access-token')).toBeUndefined();
  });

  test('provides client ticket via header', async () => {
    const { server, router } = await createServer({ headerReply: true });
    const response = await request(router)
      .get(`/ticket-by-email/${USER_INFO.email}`)
      .set('x-access-token', USER_INFO.password);
    expect(response.status).toEqual(200);
    expect(response.text).toBeTruthy();
    expect(response.get('Set-Cookie')).toBeUndefined();
    expect(response.get('x-access-token')).toBeTruthy();

    const session = response.get('x-access-token');
  });

  test('denies ticket from bad password', async () => {
    const { server, router } = await createServer();
    const response = await request(router)
      .get(`/ticket-by-email/${USER_INFO.email}`)
      .set('x-access-token', 'xxxx');
    expect(response.status).toEqual(403);
    expect(response.text).toEqual('Unauthorized');

    const cookie = response.get('Set-Cookie');
    expect(cookie.length).toBe(1);
    expect(Server.isCookieExpired(cookie[0])).toBe(true);
    expect(Server.extractTicket(cookie, 'ticket')).toEqual('');

    expect(response.get('x-access-token')).toBeUndefined();
  });

  test('denies ticket from missing password', async () => {
    const { server, router } = await createServer();
    const response = await request(router).get(
      `/ticket-by-email/${USER_INFO.email}`
    );
    expect(response.status).toEqual(400);
    expect(response.text).toEqual('Malformed request');
    expect(response.get('Set-Cookie')).toBeUndefined();
    expect(response.get('x-access-token')).toBeUndefined();
  });
});

describe('Server utility tests', () => {
  test('check empty cookie edge case', () => {
    expect(Server.extractTicket([], 'ticket')).toEqual('');
  });

  test('check missing cookie edge case', () => {
    expect(Server.extractTicket(['foo=abc'], 'ticket')).toEqual('');
  });

  test('cookies with invalid timestamps are expired', () => {
    expect(Server.isCookieExpired('Expires=lalala')).toBe(true);
  });

  test('empty cookies are expired', () => {
    expect(Server.isCookieExpired('')).toBe(true);
  });
});
