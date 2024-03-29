import { Crypto } from '../../src/index.node';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidFileKeyError } from '../../src/error/models/InvalidFileKeyError';
import { PlainFileKey } from '../../src/models/PlainFileKey';

import plainFileKeyBadVersion from '../keys/corrupted/plain_file_key_bad_version.json';

type Context = {
    plainFileKey: PlainFileKey;
};

describe('Function: Crypto.createFileDecryptionCipher', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with invalid filekey', () => {
        test('should throw an InvalidArgumentError, if filekey is falsy', () => {
            expect(() => Crypto.createFileDecryptionCipher(null)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidFileKeyError, if version of filekey is not supported', () => {
            testContext.plainFileKey = plainFileKeyBadVersion as PlainFileKey;

            expect(() => Crypto.createFileDecryptionCipher(testContext.plainFileKey)).toThrow(InvalidFileKeyError);
        });
    });
});
