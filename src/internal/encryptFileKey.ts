import forge from 'node-forge';
import { FileKeyVersion } from '../enums/FileKeyVersion';
import { UserKeyPairVersion } from '../enums/UserKeyPairVersion';
import { InvalidFileKeyError } from '../error/models/InvalidFileKeyError';
import { FileKey } from '../models/FileKey';
import { PlainFileKey } from '../models/PlainFileKey';
import { PublicKeyContainer } from '../models/PublicKeyContainer';
import { CryptoVersionChecker } from '../utils/CryptoVersionChecker';

const encryptFileKey = (
    plainFileKey: PlainFileKey,
    publicKeyContainer: PublicKeyContainer,
    cryptoVersionChecker: CryptoVersionChecker
): FileKey => {
    if (!plainFileKey.tag) {
        throw new InvalidFileKeyError();
    }

    const fileKeyVersion: FileKeyVersion = cryptoVersionChecker.getCorrectFileKeyVersion(publicKeyContainer.version, plainFileKey.version);

    const publicKey: forge.pki.rsa.PublicKey = forge.pki.publicKeyFromPem(publicKeyContainer.publicKey);
    const keyBytes: forge.Bytes = forge.util.decode64(plainFileKey.key);

    let encKeyBytes: forge.Bytes = '';
    if (publicKeyContainer.version === UserKeyPairVersion.RSA2048) {
        encKeyBytes = publicKey.encrypt(keyBytes, 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: {
                md: forge.md.sha1.create()
            }
        });
    } else if (publicKeyContainer.version === UserKeyPairVersion.RSA4096) {
        encKeyBytes = publicKey.encrypt(keyBytes, 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: {
                md: forge.md.sha256.create()
            }
        });
    }

    return {
        version: fileKeyVersion,
        key: forge.util.encode64(encKeyBytes),
        iv: plainFileKey.iv,
        tag: plainFileKey.tag
    };
};

export { encryptFileKey };
