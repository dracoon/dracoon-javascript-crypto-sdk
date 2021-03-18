import { PrivateKeyContainer } from './PrivateKeyContainer';
import { PublicKeyContainer } from './PublicKeyContainer';

export interface UserKeyPairContainer {
    privateKeyContainer: PrivateKeyContainer;
    publicKeyContainer: PublicKeyContainer;
}
