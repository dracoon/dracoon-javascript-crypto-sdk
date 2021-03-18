import { CryptoVersionMapping } from '../CryptoVersionMapping';
import { FileKeyVersion } from '../enums/FileKeyVersion';
import { PlainFileKeyVersion } from '../enums/PlainFileKeyVersion';
import { UserKeyPairVersion } from '../enums/UserKeyPairVersion';
import { VersionMismatchError } from '../error/models/VersionMismatchError';

export class CryptoVersionChecker {
    private readonly cryptoVersionMappings: CryptoVersionMapping[];

    /**
     * @param cryptoVersionMappings The supported crypto version mappings.
     */
    public constructor(cryptoVersionMappings: CryptoVersionMapping[]) {
        this.cryptoVersionMappings = [...cryptoVersionMappings];
    }

    /**
     * This method determines the correct version for a file key, given the version of a key pair and a plain file key.
     *
     * @param userKeyPairVersion The version of the user key pair.
     * @param plainFileKeyVersion The version of the plain file key.
     * @returns The correct version for the file key.
     *
     * @throws {VersionMismatchError} This error is thrown, if the provided versions are not compatible.
     */
    public getCorrectFileKeyVersion(userKeyPairVersion: UserKeyPairVersion, plainFileKeyVersion: PlainFileKeyVersion): FileKeyVersion {
        for (const versionMapping of this.cryptoVersionMappings) {
            if (versionMapping.userKeyPairVersion === userKeyPairVersion && versionMapping.plainFileKeyVersion === plainFileKeyVersion) {
                return versionMapping.fileKeyVersion;
            }
        }
        throw new VersionMismatchError();
    }

    /**
     * This method determines the correct version for a plain file key, given the version of a key pair and a file key.
     *
     * @param userKeyPairVersion The version of the user key pair.
     * @param fileKeyVersion The version of the file key.
     * @returns The correct version for the plain file key.
     *
     * @throws {VersionMismatchError} This error is thrown, if the provided versions are not compatible.
     */
    public getCorrectPlainFileKeyVersion(userKeyPairVersion: UserKeyPairVersion, fileKeyVersion: FileKeyVersion): PlainFileKeyVersion {
        for (const versionMapping of this.cryptoVersionMappings) {
            if (versionMapping.userKeyPairVersion === userKeyPairVersion && versionMapping.fileKeyVersion === fileKeyVersion) {
                return versionMapping.plainFileKeyVersion;
            }
        }
        throw new VersionMismatchError();
    }
}
