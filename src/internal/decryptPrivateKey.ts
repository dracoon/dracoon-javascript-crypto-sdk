import { pki } from 'node-forge';
import { PlainUserKeyPairContainer } from '../models/PlainUserKeyPairContainer';
import { UserKeyPairContainer } from '../models/UserKeyPairContainer';

/**
 * @deprecated The synchronous version uses plain JavaScript and is very slow with the iteraction count commonly used for encryption.
 *  Consider switching to the async version decryptPrivateKeyAsync, which uses the WebCrypto API for native speed.
 * @see decryptPrivateKeyAsync
 */
const decryptPrivateKey = (userKeyPairContainer: UserKeyPairContainer, password: string): PlainUserKeyPairContainer => {
    const encryptedPrivateKeyPEM: pki.PEM = userKeyPairContainer.privateKeyContainer.privateKey;
    const plainPrivateKey: pki.PrivateKey = pki.decryptRsaPrivateKey(encryptedPrivateKeyPEM, password);
    const plainPrivateKeyPEM: pki.PEM = pki.privateKeyToPem(plainPrivateKey);

    const plainUserKeyPairContainer: PlainUserKeyPairContainer = {
        privateKeyContainer: { ...userKeyPairContainer.privateKeyContainer },
        publicKeyContainer: { ...userKeyPairContainer.publicKeyContainer }
    };
    plainUserKeyPairContainer.privateKeyContainer.privateKey = plainPrivateKeyPEM;

    return plainUserKeyPairContainer;
};

export { decryptPrivateKey };
