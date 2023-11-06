import { Crypto } from '../../src/index.node';
import { FileDecryptionCipher } from '../../src/FileDecryptionCipher';
import { PlainFileKey } from '../../src/models/PlainFileKey';

import plainFileKey from '../keys/javascript/fk_rsa2048_aes256gcm/plain_file_key.json';

type Context = {
    plainFileKey: PlainFileKey;
};

describe('Function: Crypto.createFileDecryptionCipher', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with filekey version AES-256-GCM', () => {
        beforeEach(() => {
            testContext.plainFileKey = plainFileKey as PlainFileKey;
        });
        test('should return a new FileDecryptionCipher', () => {
            const fileDecryptionCipher: FileDecryptionCipher = Crypto.createFileDecryptionCipher(testContext.plainFileKey);

            expect(fileDecryptionCipher).toBeInstanceOf(FileDecryptionCipher);
        });
    });
});
