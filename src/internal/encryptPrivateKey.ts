import { pki } from 'node-forge';
import { PlainUserKeyPairContainer } from '../models/PlainUserKeyPairContainer';
import { UserKeyPairContainer } from '../models/UserKeyPairContainer';

/**
 * @deprecated The synchronous version uses plain JavaScript and is very slow with the iteraction count used for encryption.
 *  Consider switching to the async version encryptPrivateKeyAsync, which uses the WebCrypto API for native speed.
 * @see encryptPrivateKeyAsync
 */
const encryptPrivateKey = (plainUserKeyPairContainer: PlainUserKeyPairContainer, password: string): UserKeyPairContainer => {
    const plainPrivateKeyPEM: pki.PEM = plainUserKeyPairContainer.privateKeyContainer.privateKey;
    const plainPrivateKey: pki.PrivateKey = pki.privateKeyFromPem(plainPrivateKeyPEM);
    const options: pki.EncryptionOptions = {
        algorithm: 'aes256',
        count: 1.3e6,
        saltSize: 20,
        prfAlgorithm: 'sha1'
    };
    const encryptedPrivateKeyPEM: pki.PEM = pki.encryptRsaPrivateKey(plainPrivateKey, password, options);

    const userKeyPairContainer: UserKeyPairContainer = {
        privateKeyContainer: { ...plainUserKeyPairContainer.privateKeyContainer },
        publicKeyContainer: { ...plainUserKeyPairContainer.publicKeyContainer }
    };
    userKeyPairContainer.privateKeyContainer.privateKey = encryptedPrivateKeyPEM;

    return userKeyPairContainer;
};

export { encryptPrivateKey };
