import Debug = require('debug');
import express = require('express');
import fs = require('fs');
import https = require('https');
import tls = require('tls');
import { IncomingHttpHeaders } from 'http';
import { Authorizer, ServerConfig } from './types';

const debug = Debug('Server');
const HEADER_PASSWORD_KEY = 'x-access-token';
const COOKIE_ACCESS_KEY = 'ticket';

export class Server {
  auth: Authorizer;
  setup: boolean;

  constructor(auth: Authorizer) {
    this.auth = auth;
    this.setup = false;
  }

  async start(config: ServerConfig) {
    debug('start', config);
    if (!this.setup) {
      this.setup = true;
      await this.auth.setup();
    }

    const router = express();
    const useHeaderReply = config && config.headerReply;
    const cookieKey = config.cookieKey || COOKIE_ACCESS_KEY;
    const cookieExpiresMs = config.cookieExpiresMs || 0;

    router.get(
      '/public-key',
      async (req: express.Request, res: express.Response) => {
        debug('/public-key');
        res.status(200).send(await this.auth.getPublicKey());
      }
    );

    router.get(
      '/ticket-by-email/:email',
      async (req: express.Request, res: express.Response) => {
        const email = req.params.email;
        const password = req.headers[HEADER_PASSWORD_KEY] as string;
        const credentials = { email, password };

        debug('/ticket-by-email/', email, password !== undefined);
        if (!email || !password) {
          res.status(400).send('Malformed request');
          return;
        }

        const session = await this.auth.authenticateUser(credentials);
        if (!session || !session.session) {
          res.set(HEADER_PASSWORD_KEY);
          res.clearCookie(cookieKey);
          res.status(403).send('Unauthorized');
        } else {
          if (useHeaderReply) {
            res.set(HEADER_PASSWORD_KEY, session.session);
          } else {
            const cookieOpts = {
              expires: new Date(Date.now() + cookieExpiresMs),
            };
            res.cookie(cookieKey, session.session, cookieOpts);
          }
          res.status(200).send('OK');
        }
      }
    );

    let listen = () => {
      debug('http listen', config.port);
      router.listen(config.port);
    };

    if (config.https) {
      const server = https.createServer(
        {
          SNICallback: (servername: string, cb) => {
            debug(
              'SNICallback',
              config.https!.keyFileName,
              config.https!.certFileName,
              config.https!.caFileName
            );
            const ctx = tls.createSecureContext({
              key: fs.readFileSync(config.https!.keyFileName, 'utf8'),
              cert: fs.readFileSync(config.https!.certFileName, 'utf8'),
              ca: fs.readFileSync(config.https!.caFileName, 'utf8'),
            });
            debug('SNICallback continues');
            cb(null, ctx);
          },
        },
        router
      );
      listen = () => {
        debug('https listen', config.port);
        server.listen(config.port);
      };
    }

    if (config.port) {
      listen();
    }
    return router;
  }

  static extractTicket(cookies: string[], cookieKey: string): string {
    const ticketRE = new RegExp(`${cookieKey}\s*=\s*([^;]*)\s*`);
    for (let i = 0; i < cookies.length; i++) {
      const cookieStr = cookies[i];
      const m = cookieStr.match(ticketRE);
      if (m && m.length > 0) {
        const cookie = m[1];
        if (Server.isCookieExpired(cookieStr)) {
          return '';
        } else {
          return cookie;
        }
      }
    }
    return '';
  }

  static isCookieExpired(cookieStr: string): boolean {
    const m = cookieStr.match(/Expires\s*=\s*([^;]*)/);
    if (!m || m.length < 1) {
      return true;
    }
    const dateStr = m[1];
    const expires = new Date(dateStr);
    const t = expires.getTime();
    return isNaN(t) || t < Date.now();
  }
}
