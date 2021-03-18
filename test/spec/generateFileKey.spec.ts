import base64 from 'base64-js';
import { Crypto } from '../../src/Crypto';
import { PlainFileKeyVersion } from '../../src/enums/PlainFileKeyVersion';
import { PlainFileKey } from '../../src/models/PlainFileKey';

type Context = {
    version: PlainFileKeyVersion;
};

describe('Function: Crypto.generateFileKey', () => {
    describe('with filekey version AES-256-GCM', () => {
        beforeEach(function (this: Context) {
            this.version = PlainFileKeyVersion.AES256GCM;
        });
        it('should return a PlainFileKey with the correct properties', function (this: Context) {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(this.version);

            expect(Object.keys(plainFileKey)).toContain('version');
            expect(Object.keys(plainFileKey)).toContain('key');
            expect(Object.keys(plainFileKey)).toContain('iv');
            expect(Object.keys(plainFileKey)).toContain('tag');
        });
        it('should return a PlainFileKey with the correct crypto version', function (this: Context) {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(this.version);

            expect(plainFileKey.version).toEqual(PlainFileKeyVersion.AES256GCM);
        });
        it('should return a PlainFileKey with a 256 bit key base64 encoded', function (this: Context) {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(this.version);
            const bitLength: number = base64.byteLength(plainFileKey.key) * 8;

            expect(bitLength).toEqual(256);
        });
        it('should return a PlainFileKey with a 96 bit iv base64 encoded', function (this: Context) {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(this.version);
            const bitLength: number = base64.byteLength(plainFileKey.iv) * 8;

            expect(bitLength).toEqual(96);
        });
        it('should return a PlainFileKey with a tag equal to null', function (this: Context) {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(this.version);

            expect(plainFileKey.tag).toBeNull();
        });
    });
});
