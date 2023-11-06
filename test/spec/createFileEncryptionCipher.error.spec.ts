import { Crypto } from '../../src/index.node';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidFileKeyError } from '../../src/error/models/InvalidFileKeyError';
import { PlainFileKey } from '../../src/models/PlainFileKey';

import plainFileKeyBadVersion from '../keys/corrupted/plain_file_key_bad_version.json';

type Context = {
    plainFileKey: PlainFileKey;
};

describe('Function: Crypto.createFileEncryptionCipher', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with invalid filekey', () => {
        test('should throw an InvalidArgumentError, if filekey is falsy', () => {
            expect(() => Crypto.createFileEncryptionCipher(null)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidFileKeyError, if version of filekey is not supported', () => {
            testContext.plainFileKey = plainFileKeyBadVersion as PlainFileKey;

            expect(() => Crypto.createFileEncryptionCipher(testContext.plainFileKey)).toThrow(InvalidFileKeyError);
        });
    });
});
