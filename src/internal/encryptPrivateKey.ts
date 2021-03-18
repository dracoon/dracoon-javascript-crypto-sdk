import forge from 'node-forge';
import { PlainUserKeyPairContainer } from '../models/PlainUserKeyPairContainer';
import { UserKeyPairContainer } from '../models/UserKeyPairContainer';

const encryptPrivateKey = (plainUserKeyPairContainer: PlainUserKeyPairContainer, password: string): UserKeyPairContainer => {
    const plainPrivateKeyPEM: forge.pki.PEM = plainUserKeyPairContainer.privateKeyContainer.privateKey;
    const plainPrivateKey: forge.pki.PrivateKey = forge.pki.privateKeyFromPem(plainPrivateKeyPEM);
    const options: forge.pki.EncryptionOptions = {
        algorithm: 'aes256',
        count: 10000,
        saltSize: 128
    };
    const encryptedPrivateKeyPEM: forge.pki.PEM = forge.pki.encryptRsaPrivateKey(plainPrivateKey, password, options);

    const userKeyPairContainer: UserKeyPairContainer = {
        privateKeyContainer: { ...plainUserKeyPairContainer.privateKeyContainer },
        publicKeyContainer: { ...plainUserKeyPairContainer.publicKeyContainer }
    };
    userKeyPairContainer.privateKeyContainer.privateKey = encryptedPrivateKeyPEM;

    return userKeyPairContainer;
};

export { encryptPrivateKey };
