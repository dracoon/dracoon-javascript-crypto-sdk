import { Crypto } from '../../src/Crypto';
import { FileEncryptionCipher } from '../../src/FileEncryptionCipher';
import { PlainFileKey } from '../../src/models/PlainFileKey';

import plainFileKey from '../keys/javascript/fk_rsa2048_aes256gcm/plain_file_key.json';

type Context = {
    plainFileKey: PlainFileKey;
};

describe('Function: Crypto.createFileEncryptionCipher', () => {
    describe('with filekey version AES-256-GCM', () => {
        beforeEach(function (this: Context) {
            this.plainFileKey = plainFileKey as PlainFileKey;
        });
        it('should return a new FileEncryptionCipher', function (this: Context) {
            const fileEncryptionCipher: FileEncryptionCipher = Crypto.createFileEncryptionCipher(this.plainFileKey);

            expect(fileEncryptionCipher).toBeInstanceOf(FileEncryptionCipher);
        });
    });
});
