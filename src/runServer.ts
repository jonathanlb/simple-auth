import { Server } from './Server';
import { ServerConfig } from './types';
import { SimpleAuth } from './SimpleAuth';

const authConfig = {
  dbFileName: '',
  privateKeyFileName: '',
  publicKeyFileName: '',
};
const serverConfig = {
  port: 3000,
};

const auth = new SimpleAuth(authConfig);
const server = new Server(auth);
server.start(serverConfig);
