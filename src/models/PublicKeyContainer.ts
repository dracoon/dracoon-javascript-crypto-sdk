import { pki } from 'node-forge';
import { UserKeyPairVersion } from '../enums/UserKeyPairVersion';

export interface PublicKeyContainer {
    version: UserKeyPairVersion;
    publicKey: pki.PEM;
    createdAt?: Date;
    createdBy?: number;
    expireAt?: Date;
}
