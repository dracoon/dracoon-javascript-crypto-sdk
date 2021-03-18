import { Crypto } from '../../src/Crypto';
import { PlainFileKeyVersion } from '../../src/enums/PlainFileKeyVersion';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidVersionError } from '../../src/error/models/InvalidVersionError';

type Context = {
    version: PlainFileKeyVersion;
};

describe('Function: Crypto.generateFileKey', () => {
    describe('with invalid filekey version', () => {
        it('should throw an InvalidArgumentError, if version is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.generateFileKey(null);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidVersionError, if version is not supported', function (this: Context) {
            let someError = null;

            try {
                Crypto.generateFileKey('AES-128-GCM' as PlainFileKeyVersion);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidVersionError);
        });
    });
});
