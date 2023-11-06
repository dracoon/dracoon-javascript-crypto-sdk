import { Base64, random, util } from 'node-forge';
import { PlainFileKeyVersion } from '../enums/PlainFileKeyVersion';
import { PlainFileKey } from '../models/PlainFileKey';

const generateFileKey = (version: PlainFileKeyVersion): PlainFileKey => {
    const key: string = random.getBytesSync(32);
    const iv: string = random.getBytesSync(12);

    const encodedKey: Base64 = util.encode64(key);
    const encodedIv: Base64 = util.encode64(iv);

    return {
        version: version,
        key: encodedKey,
        iv: encodedIv,
        tag: null
    };
};

export { generateFileKey };
