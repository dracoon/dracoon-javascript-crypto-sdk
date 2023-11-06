import { Bytes, md, pki, util } from 'node-forge';
import { PlainFileKeyVersion } from '../enums/PlainFileKeyVersion';
import { UserKeyPairVersion } from '../enums/UserKeyPairVersion';
import { InvalidFileKeyError } from '../error/models/InvalidFileKeyError';
import { FileKey } from '../models/FileKey';
import { PlainFileKey } from '../models/PlainFileKey';
import { PrivateKeyContainer } from '../models/PrivateKeyContainer';
import { CryptoVersionChecker } from '../utils/CryptoVersionChecker';

const decryptFileKey = (
    fileKey: FileKey,
    privateKeyContainer: PrivateKeyContainer,
    cryptoVersionChecker: CryptoVersionChecker
): PlainFileKey => {
    if (!fileKey.tag) {
        throw new InvalidFileKeyError();
    }

    const plainFileKeyVersion: PlainFileKeyVersion = cryptoVersionChecker.getCorrectPlainFileKeyVersion(
        privateKeyContainer.version,
        fileKey.version
    );

    const privateKey: pki.rsa.PrivateKey = pki.privateKeyFromPem(privateKeyContainer.privateKey);
    const keyBytes: Bytes = util.decode64(fileKey.key);

    let decKeyBytes: Bytes = '';
    if (privateKeyContainer.version === UserKeyPairVersion.RSA2048) {
        decKeyBytes = privateKey.decrypt(keyBytes, 'RSA-OAEP', {
            md: md.sha256.create(),
            mgf1: {
                md: md.sha1.create()
            }
        });
    } else if (privateKeyContainer.version === UserKeyPairVersion.RSA4096) {
        decKeyBytes = privateKey.decrypt(keyBytes, 'RSA-OAEP', {
            md: md.sha256.create(),
            mgf1: {
                md: md.sha256.create()
            }
        });
    }

    return {
        version: plainFileKeyVersion,
        key: util.encode64(decKeyBytes),
        iv: fileKey.iv,
        tag: fileKey.tag
    };
};

export { decryptFileKey };
