import { Command } from 'commander';
import { Server } from './Server';
import { ServerConfig } from './types';
import { SimpleAuth } from './SimpleAuth';

// tslint:disable-next-line:no-any
export function createAuth(opts: any): SimpleAuth {
  const config = {
    dbFileName: opts.authDb,
    privateKeyFileName: opts.privateKey,
    publicKeyFileName: opts.publicKey,
  };
  return new SimpleAuth(config);
}

// tslint:disable-next-line:no-any
export function parseCli(argv: string[]): any {
  const cli = new Command();
  cli
    .description('Start simpleAuth server')
    .option('-p, --port <port-number>', 'Server port', parseInt)
    .requiredOption('-a, --auth-db <file-name>', 'SimpleAuth sqlite3 file name')
    .requiredOption(
      '-K, --private-key <file-name>',
      '.SimpleAuth private key file name'
    )
    .requiredOption(
      '-k, --public-key <file-name>',
      'SimpleAuth public key file name'
    )
    .option('-c, --ca-file <file-name>', 'Https certificate authority file')
    .option('-C, --cert-file <file-name>', 'Https local certificate file')
    .option('-H, --https-key-file <file-name>', 'Https local private-key file')
    .option(
      '-m, --expiry-minutes <minutes>',
      'Duration in minutes tickets are valid',
      parseInt
    )
    .option('-x, --reply-in-header', 'Reply in x-access-token header')
    .option(
      '-t, --cookie-key <key-value>',
      'Reply in to the cookie key-value pair, defaults to ticket'
    )
    .parse(argv);

  const opts = cli.opts();
  if (opts.caFile || opts.certFile || opts.httpsKeyFile) {
    if (!opts.caFile || !opts.certFile || !opts.httpsKeyFile) {
      throw new Error('To use HTTPS, you must specify ca, cert, and key files');
    }
  }

  return opts;
}

export function start(argv: string[]) {
  const opts = parseCli(argv);
  const auth = createAuth(opts);
  startServer(auth, opts);
}

// tslint:disable-next-line:no-any
export function startServer(auth: SimpleAuth, opts: any) {
  const server = new Server(auth);
  const config: ServerConfig = {
    cookieExpiresMs: (opts.expiryMinutes || 60) * 60000,
    port: opts.port,
  };

  if (opts.caFile || opts.certFile || opts.httpsKeyFile) {
    config.https = {
      caFileName: opts.caFile,
      certFileName: opts.certFile,
      keyFileName: opts.httpsKeyFile,
    };
  }

  server.start(config);
}
