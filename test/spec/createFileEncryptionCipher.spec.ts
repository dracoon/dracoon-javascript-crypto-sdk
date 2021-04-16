import { Crypto } from '../../src/index';
import { FileEncryptionCipher } from '../../src/FileEncryptionCipher';
import { PlainFileKey } from '../../src/models/PlainFileKey';

import plainFileKey from '../keys/javascript/fk_rsa2048_aes256gcm/plain_file_key.json';

type Context = {
    plainFileKey: PlainFileKey;
};

describe('Function: Crypto.createFileEncryptionCipher', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with filekey version AES-256-GCM', () => {
        beforeEach(() => {
            testContext.plainFileKey = plainFileKey as PlainFileKey;
        });
        test('should return a new FileEncryptionCipher', () => {
            const fileEncryptionCipher: FileEncryptionCipher = Crypto.createFileEncryptionCipher(testContext.plainFileKey);

            expect(fileEncryptionCipher).toBeInstanceOf(FileEncryptionCipher);
        });
    });
});
