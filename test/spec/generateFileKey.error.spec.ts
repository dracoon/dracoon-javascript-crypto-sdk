import { Crypto } from '../../src/index';
import { PlainFileKeyVersion } from '../../src/enums/PlainFileKeyVersion';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidVersionError } from '../../src/error/models/InvalidVersionError';

type Context = {
    version: PlainFileKeyVersion;
};

describe('Function: Crypto.generateFileKey', () => {
    describe('with invalid filekey version', () => {
        test('should throw an InvalidArgumentError, if version is falsy', () => {
            expect(() => Crypto.generateFileKey(null)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidVersionError, if version is not supported', () => {
            expect(() => Crypto.generateFileKey('AES-128-GCM' as PlainFileKeyVersion)).toThrow(InvalidVersionError);
        });
    });
});
