import { setCryptoWorker } from './internal/cryptoWorker';
import { webcrypto } from 'crypto';

setCryptoWorker(webcrypto as unknown as Crypto);

export { Crypto } from './Crypto';
