import { PrivateKeyContainer } from './PrivateKeyContainer';
import { PublicKeyContainer } from './PublicKeyContainer';

export interface PlainUserKeyPairContainer {
    privateKeyContainer: PrivateKeyContainer;
    publicKeyContainer: PublicKeyContainer;
}
