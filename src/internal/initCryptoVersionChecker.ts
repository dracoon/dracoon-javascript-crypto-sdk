import { CryptoVersionMapping } from '../CryptoVersionMapping';
import { CryptoVersionChecker } from '../utils/CryptoVersionChecker';
import { FileKeyVersion } from '../enums/FileKeyVersion';
import { PlainFileKeyVersion } from '../enums/PlainFileKeyVersion';
import { UserKeyPairVersion } from '../enums/UserKeyPairVersion';

const initCryptoVersionChecker = (): CryptoVersionChecker => {
    const cryptoVersionMappings: CryptoVersionMapping[] = [
        new CryptoVersionMapping(UserKeyPairVersion.RSA2048, FileKeyVersion.RSA2048_AES256GCM, PlainFileKeyVersion.AES256GCM),
        new CryptoVersionMapping(UserKeyPairVersion.RSA4096, FileKeyVersion.RSA4096_AES256GCM, PlainFileKeyVersion.AES256GCM)
    ];
    return new CryptoVersionChecker(cryptoVersionMappings);
};

export { initCryptoVersionChecker };
