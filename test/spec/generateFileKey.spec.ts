import base64 from 'base64-js';
import { Crypto } from '../../src/index.node';
import { PlainFileKeyVersion } from '../../src/enums/PlainFileKeyVersion';
import { PlainFileKey } from '../../src/models/PlainFileKey';

type Context = {
    version: PlainFileKeyVersion;
};

describe('Function: Crypto.generateFileKey', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with filekey version AES-256-GCM', () => {
        beforeEach(() => {
            testContext.version = PlainFileKeyVersion.AES256GCM;
        });
        test('should return a PlainFileKey with the correct properties', () => {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(testContext.version);

            expect(Object.keys(plainFileKey)).toContain('version');
            expect(Object.keys(plainFileKey)).toContain('key');
            expect(Object.keys(plainFileKey)).toContain('iv');
            expect(Object.keys(plainFileKey)).toContain('tag');
        });
        test('should return a PlainFileKey with the correct crypto version', () => {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(testContext.version);

            expect(plainFileKey.version).toBe(PlainFileKeyVersion.AES256GCM);
        });
        test('should return a PlainFileKey with a 256 bit key base64 encoded', () => {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(testContext.version);
            const bitLength: number = base64.byteLength(plainFileKey.key) * 8;

            expect(bitLength).toBe(256);
        });
        test('should return a PlainFileKey with a 96 bit iv base64 encoded', () => {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(testContext.version);
            const bitLength: number = base64.byteLength(plainFileKey.iv) * 8;

            expect(bitLength).toBe(96);
        });
        test('should return a PlainFileKey with a tag equal to null', () => {
            const plainFileKey: PlainFileKey = Crypto.generateFileKey(testContext.version);

            expect(plainFileKey.tag).toBeNull();
        });
    });
});
