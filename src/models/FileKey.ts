import { Base64 } from 'node-forge';
import { FileKeyVersion } from '../enums/FileKeyVersion';

export interface FileKey {
    version: FileKeyVersion;
    key: Base64;
    iv: Base64;
    tag: Base64;
}
