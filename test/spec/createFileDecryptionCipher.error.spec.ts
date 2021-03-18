import { Crypto } from '../../src/Crypto';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidFileKeyError } from '../../src/error/models/InvalidFileKeyError';
import { PlainFileKey } from '../../src/models/PlainFileKey';

import plainFileKeyBadVersion from '../keys/corrupted/plain_file_key_bad_version.json';

type Context = {
    plainFileKey: PlainFileKey;
};

describe('Function: Crypto.createFileDecryptionCipher', () => {
    describe('with invalid filekey', () => {
        it('should throw an InvalidArgumentError, if filekey is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.createFileDecryptionCipher(null);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidFileKeyError, if version of filekey is not supported', function (this: Context) {
            this.plainFileKey = plainFileKeyBadVersion as PlainFileKey;
            let someError = null;

            try {
                Crypto.createFileDecryptionCipher(this.plainFileKey);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidFileKeyError);
        });
    });
});
