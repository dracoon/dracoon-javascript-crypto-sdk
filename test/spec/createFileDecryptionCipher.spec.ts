import { Crypto } from '../../src/Crypto';
import { FileDecryptionCipher } from '../../src/FileDecryptionCipher';
import { PlainFileKey } from '../../src/models/PlainFileKey';

import plainFileKey from '../keys/javascript/fk_rsa2048_aes256gcm/plain_file_key.json';

type Context = {
    plainFileKey: PlainFileKey;
};

describe('Function: Crypto.createFileDecryptionCipher', () => {
    describe('with filekey version AES-256-GCM', () => {
        beforeEach(function (this: Context) {
            this.plainFileKey = plainFileKey as PlainFileKey;
        });
        it('should return a new FileDecryptionCipher', function (this: Context) {
            const fileDecryptionCipher: FileDecryptionCipher = Crypto.createFileDecryptionCipher(this.plainFileKey);

            expect(fileDecryptionCipher).toBeInstanceOf(FileDecryptionCipher);
        });
    });
});
