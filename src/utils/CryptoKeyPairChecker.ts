import { UserKeyPairVersion } from '../enums/UserKeyPairVersion';
import { PlainUserKeyPairContainer } from '../models/PlainUserKeyPairContainer';
import { PrivateKeyContainer } from '../models/PrivateKeyContainer';
import { PublicKeyContainer } from '../models/PublicKeyContainer';
import { UserKeyPairContainer } from '../models/UserKeyPairContainer';

export class CryptoKeyPairChecker {
    public static checkKeyPairContainer(keyPairContainer: UserKeyPairContainer | PlainUserKeyPairContainer): boolean {
        if (!keyPairContainer || !keyPairContainer.privateKeyContainer || !keyPairContainer.publicKeyContainer) {
            return false;
        }

        const privateKeyVersion: UserKeyPairVersion = keyPairContainer.privateKeyContainer.version;
        const publicKeyVersion: UserKeyPairVersion = keyPairContainer.publicKeyContainer.version;
        if (privateKeyVersion !== publicKeyVersion) {
            return false;
        }

        const privateKeyContainerValid: boolean = CryptoKeyPairChecker.checkKeyContainer(keyPairContainer.privateKeyContainer);
        const publicKeyContainerValid: boolean = CryptoKeyPairChecker.checkKeyContainer(keyPairContainer.publicKeyContainer);
        if (!privateKeyContainerValid || !publicKeyContainerValid) {
            return false;
        }

        return true;
    }

    public static checkKeyContainer(keyContainer: PrivateKeyContainer | PublicKeyContainer): boolean {
        if (!keyContainer || !keyContainer.version) {
            return false;
        }

        if (!Object.values(UserKeyPairVersion).includes(keyContainer.version)) {
            return false;
        }

        return true;
    }
}
