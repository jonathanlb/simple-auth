import { createAuth, parseCli, start } from '../src/ServerRunner';
import commander = require('commander');

const PRIVATE_KEY = 'test/jwtRS256.key';
const PUBLIC_KEY = 'test/jwtRS256.key.pub';

describe('ServerRunner functionality', () => {
  beforeAll(() => {
    commander.exitOverride(e => {
      console.error('commander throwing', e);
      throw new Error(e.toString());
    });
  });

  test('Creates authenticator', async () => {
    const auth = createAuth({
      dbFileName: ':memory:',
      privateKeyFileName: PRIVATE_KEY,
      publicKeyFileName: PUBLIC_KEY,
    });
    expect(auth).toBeDefined();
  });

  test('Enforces https trifecta', () => {
    const argv = `node someScript.js -a :memory -K ${PRIVATE_KEY} -k ${PUBLIC_KEY} -H https.key`.split(
      /\s+/
    );
    expect(() => parseCli(argv)).toThrow();
  });

  test('Evergreen dry run', async () => {
    const argv = `node someScript.js -a :memory -K ${PRIVATE_KEY} -k ${PUBLIC_KEY}`.split(
      /\s+/
    );
    start(argv);
  });
});
