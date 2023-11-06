import { pki } from 'node-forge';
import { UserKeyPairVersion } from '../enums/UserKeyPairVersion';
import { InvalidVersionError } from '../error/models/InvalidVersionError';
import { PlainUserKeyPairContainer } from '../models/PlainUserKeyPairContainer';

const generatePlainUserKeyPair = (version: UserKeyPairVersion): Promise<PlainUserKeyPairContainer> => {
    const options: pki.rsa.GenerateKeyPairOptions = {};
    if (version === UserKeyPairVersion.RSA2048) {
        options.bits = 2048;
        options.e = 0x10001;
        options.workers = -1;
    } else if (version === UserKeyPairVersion.RSA4096) {
        options.bits = 4096;
        options.e = 0x10001;
        options.workers = -1;
    } else {
        throw new InvalidVersionError();
    }

    return new Promise((resolve, reject) => {
        pki.rsa.generateKeyPair(options, (err, keypair) => {
            if (err) {
                reject(err);
            } else {
                const plainUserKeyPairContainer: PlainUserKeyPairContainer = {
                    privateKeyContainer: {
                        version: version,
                        privateKey: pki.privateKeyToPem(keypair.privateKey)
                    },
                    publicKeyContainer: {
                        version: version,
                        publicKey: pki.publicKeyToPem(keypair.publicKey)
                    }
                };
                resolve(plainUserKeyPairContainer);
            }
        });
    });
};

export { generatePlainUserKeyPair };
