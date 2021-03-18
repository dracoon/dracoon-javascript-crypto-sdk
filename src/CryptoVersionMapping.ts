import { FileKeyVersion } from './enums/FileKeyVersion';
import { PlainFileKeyVersion } from './enums/PlainFileKeyVersion';
import { UserKeyPairVersion } from './enums/UserKeyPairVersion';

export class CryptoVersionMapping {
    public readonly userKeyPairVersion: UserKeyPairVersion;
    public readonly fileKeyVersion: FileKeyVersion;
    public readonly plainFileKeyVersion: PlainFileKeyVersion;

    public constructor(userKeyPairVersion: UserKeyPairVersion, fileKeyVersion: FileKeyVersion, plainFileKeyVersion: PlainFileKeyVersion) {
        this.userKeyPairVersion = userKeyPairVersion;
        this.fileKeyVersion = fileKeyVersion;
        this.plainFileKeyVersion = plainFileKeyVersion;
    }
}
