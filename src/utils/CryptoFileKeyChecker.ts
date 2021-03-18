import { FileKeyVersion } from '../enums/FileKeyVersion';
import { PlainFileKeyVersion } from '../enums/PlainFileKeyVersion';
import { FileKey } from '../models/FileKey';
import { PlainFileKey } from '../models/PlainFileKey';

export class CryptoFileKeyChecker {
    public static checkPlainFileKey(plainFileKey: PlainFileKey): boolean {
        if (!plainFileKey || !plainFileKey.version || !plainFileKey.key || !plainFileKey.iv) {
            return false;
        }
        if (!Object.values(PlainFileKeyVersion).includes(plainFileKey.version)) {
            return false;
        }
        return true;
    }

    public static checkFileKey(fileKey: FileKey): boolean {
        if (!fileKey || !fileKey.version || !fileKey.key || !fileKey.iv || !fileKey.tag) {
            return false;
        }
        if (!Object.values(FileKeyVersion).includes(fileKey.version)) {
            return false;
        }
        return true;
    }
}
