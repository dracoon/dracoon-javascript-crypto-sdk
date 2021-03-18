import { Base64 } from 'node-forge';
import { PlainFileKeyVersion } from '../enums/PlainFileKeyVersion';

export interface PlainFileKey {
    version: PlainFileKeyVersion;
    key: Base64;
    iv: Base64;
    tag: Base64 | null;
}
