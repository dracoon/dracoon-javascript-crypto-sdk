import base64 from 'base64-js';
import fs from 'fs';
import path from 'path';
import { Crypto, PlainFileKeyVersion, UserKeyPairVersion, PlainDataContainer } from '../lib/bundle.js';

const PASSWORD = 'Qwer1234!';
const BASE64 = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=';

const perform = async () => {
    const userKeyPair2048 = await Crypto.generateUserKeyPair(UserKeyPairVersion.RSA2048, PASSWORD);
    const userKeyPair4096 = await Crypto.generateUserKeyPair(UserKeyPairVersion.RSA4096, PASSWORD);

    const plainUserKeyPair2048 = Crypto.decryptPrivateKey(userKeyPair2048, PASSWORD);
    const plainUserKeyPair4096 = Crypto.decryptPrivateKey(userKeyPair4096, PASSWORD);

    const plainFileKey = Crypto.generateFileKey(PlainFileKeyVersion.AES256GCM);

    const fileEncryptionCipher = Crypto.createFileEncryptionCipher(plainFileKey);

    // Encryption
    const plainByteArray = base64.toByteArray(BASE64);
    const encDataContainer1 = fileEncryptionCipher.processBytes(new PlainDataContainer(plainByteArray));
    const encByteArray1 = encDataContainer1.getContent();

    const encDataContainer2 = fileEncryptionCipher.doFinal();
    const encByteArray2 = encDataContainer2.getContent();
    const tag = encDataContainer2.getTag();

    const encByteArray = new Uint8Array([...encByteArray1, ...encByteArray2]);
    const encBASE64 = base64.fromByteArray(encByteArray);

    plainFileKey.tag = tag;
    const encFileKey2048 = Crypto.encryptFileKey(plainFileKey, plainUserKeyPair2048.publicKeyContainer);
    const encFileKey4096 = Crypto.encryptFileKey(plainFileKey, plainUserKeyPair4096.publicKeyContainer);

    // --- WRITE TO FILES ---

    // Filekeys 2048
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/fk_rsa2048_aes256gcm/enc_file_key.json'),
        JSON.stringify(encFileKey2048),
        () => {}
    );
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/fk_rsa2048_aes256gcm/plain_file_key.json'),
        JSON.stringify(plainFileKey),
        () => {}
    );
    // Filekeys 4096
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/fk_rsa4096_aes256gcm/enc_file_key.json'),
        JSON.stringify(encFileKey4096),
        () => {}
    );
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/fk_rsa4096_aes256gcm/plain_file_key.json'),
        JSON.stringify(plainFileKey),
        () => {}
    );

    // Keypairs 2048
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/kp_rsa2048/plain_private_key.json'),
        JSON.stringify(plainUserKeyPair2048.privateKeyContainer),
        () => {}
    );
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/kp_rsa2048/private_key.json'),
        JSON.stringify(userKeyPair2048.privateKeyContainer),
        () => {}
    );
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/kp_rsa2048/public_key.json'),
        JSON.stringify(userKeyPair2048.publicKeyContainer),
        () => {}
    );
    // Keypairs 4096
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/kp_rsa4096/plain_private_key.json'),
        JSON.stringify(plainUserKeyPair4096.privateKeyContainer),
        () => {}
    );
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/kp_rsa4096/private_key.json'),
        JSON.stringify(userKeyPair4096.privateKeyContainer),
        () => {}
    );
    fs.writeFile(
        path.join(path.resolve(), '/scripts/keys/kp_rsa4096/public_key.json'),
        JSON.stringify(userKeyPair4096.publicKeyContainer),
        () => {}
    );

    // Password
    fs.writeFile(path.join(path.resolve(), '/scripts/password.txt'), PASSWORD, () => {});

    // BASE64
    fs.writeFile(path.join(path.resolve(), '/scripts/files/plain_file.b64'), BASE64, () => {});
    fs.writeFile(path.join(path.resolve(), '/scripts/files/enc_file.b64'), encBASE64, () => {});
};

perform();
