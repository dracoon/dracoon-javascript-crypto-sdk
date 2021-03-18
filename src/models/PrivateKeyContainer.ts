import { pki } from 'node-forge';
import { UserKeyPairVersion } from '../enums/UserKeyPairVersion';

export interface PrivateKeyContainer {
    version: UserKeyPairVersion;
    privateKey: pki.PEM;
    createdAt?: Date;
    createdBy?: number;
    expireAt?: Date;
}
