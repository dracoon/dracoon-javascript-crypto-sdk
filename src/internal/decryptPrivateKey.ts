import forge from 'node-forge';
import { PlainUserKeyPairContainer } from '../models/PlainUserKeyPairContainer';
import { UserKeyPairContainer } from '../models/UserKeyPairContainer';

const decryptPrivateKey = (userKeyPairContainer: UserKeyPairContainer, password: string): PlainUserKeyPairContainer => {
    const encryptedPrivateKeyPEM: forge.pki.PEM = userKeyPairContainer.privateKeyContainer.privateKey;
    const plainPrivateKey: forge.pki.PrivateKey = forge.pki.decryptRsaPrivateKey(encryptedPrivateKeyPEM, password);
    const plainPrivateKeyPEM: forge.pki.PEM = forge.pki.privateKeyToPem(plainPrivateKey);

    const plainUserKeyPairContainer: PlainUserKeyPairContainer = {
        privateKeyContainer: { ...userKeyPairContainer.privateKeyContainer },
        publicKeyContainer: { ...userKeyPairContainer.publicKeyContainer }
    };
    plainUserKeyPairContainer.privateKeyContainer.privateKey = plainPrivateKeyPEM;

    return plainUserKeyPairContainer;
};

export { decryptPrivateKey };
