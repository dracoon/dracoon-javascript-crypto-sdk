import { asn1, pem, pki, util } from 'node-forge';
import { NotSupportedError } from '../../error/models/NotSupportedError';
import { PlainUserKeyPairContainer } from '../../models/PlainUserKeyPairContainer';
import { UserKeyPairContainer } from '../../models/UserKeyPairContainer';
import { deriveKey } from './deriveKey';
import { getCryptoWorker } from '../cryptoWorker';
import { CipherByteLengthMap, PrfToHashAlg } from './maps';
import { DecryptionParams, EncryptPrivateKeyParams, SupportedCipher, SupportedPrf, ValidKeyByteLength, ValidKeyLength } from './models';
import { Utils } from './utils';
import {
    EncryptedPrivateKeyCapture,
    encryptedPrivateKeyValidator,
    PBES2AlgorithmsCapture,
    PBES2AlgorithmsValidator,
    validate
} from './validator';
import { Encoding } from '../../models/Encoding.enum';

export async function decryptPrivateKeyAsync(
    userKeyPairContainer: UserKeyPairContainer,
    password: string
): Promise<PlainUserKeyPairContainer> {
    const encryptedPrivateKeyPEM: pki.PEM = userKeyPairContainer.privateKeyContainer.privateKey;
    const plainPrivateKeyPEM: pki.PEM = await decryptRsaPrivateKeyAsync(encryptedPrivateKeyPEM, password, getCryptoWorker());

    const plainUserKeyPairContainer: PlainUserKeyPairContainer = {
        privateKeyContainer: { ...userKeyPairContainer.privateKeyContainer },
        publicKeyContainer: { ...userKeyPairContainer.publicKeyContainer }
    };
    plainUserKeyPairContainer.privateKeyContainer.privateKey = plainPrivateKeyPEM;

    return plainUserKeyPairContainer;
}

/**
 * Decrypts an RSA private key.
 *
 * inspired by
 * https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/lib/pbe.js#L537
 *
 * @param pemStr the PEM-formatted EncryptedPrivateKeyInfo to decrypt.
 * @param password the password to use.
 * @param cryptoWorker the crypto implementation that will perform key derivation and enctyption.
 *
 * @return the PEM-formatted RSA key.
 */
export async function decryptRsaPrivateKeyAsync(pemStr: string, password: string, cryptoWorker: Crypto): Promise<pki.PEM> {
    const msg: pem.ObjectPEM = pem.decode(pemStr)[0];

    if (msg.type !== 'ENCRYPTED PRIVATE KEY') {
        throw new Error("Not in expected format of 'ENCRYPTED PRIVATE KEY'");
    }

    const decryptedAsn1: asn1.Asn1 = await decryptPrivateKeyInfo(asn1.fromDer(msg.body), password, cryptoWorker);

    const privateKey: pki.PrivateKey = pki.privateKeyFromAsn1(decryptedAsn1);
    const privateKeyPem: pki.PEM = pki.privateKeyToPem(privateKey);

    return privateKeyPem;
}

/**
 * Decrypts a ASN.1 PrivateKeyInfo object.
 *
 * @param obj the ASN.1 EncryptedPrivateKeyInfo object.
 * @param password the password to decrypt with.
 * @param cryptoWorker the crypto implementation that will perform key derivation and enctyption.
 *
 * @return the ASN.1 PrivateKeyInfo.
 */
async function decryptPrivateKeyInfo(obj: asn1.Asn1, password: string, cryptoWorker: Crypto): Promise<asn1.Asn1> {
    const capture: EncryptedPrivateKeyCapture = validate<EncryptedPrivateKeyCapture>(obj, encryptedPrivateKeyValidator);

    const oid: string = asn1.derToOid(util.createBuffer(capture.encryptionOid));

    const decryptionParams: DecryptionParams = getDecryptionParams(oid, capture.encryptionParams);

    const encryptedDataView: Uint8Array = Utils.stringAsArrayBuffer(capture.encryptedData);

    const decryptedData: ArrayBuffer = await deriveKeyAndDecrypt(
        {
            contentEncryptionAlgorithm: {
                name: 'AES-CBC',
                length: (decryptionParams.derivedKeyLengthBytes * 8) as ValidKeyLength,
                iv: Utils.stringAsArrayBuffer(decryptionParams.iv)
            },
            hashingParams: {
                hmacHashAlgorithm: PrfToHashAlg[decryptionParams.hashAlgorithm],
                iterationCount: decryptionParams.iterationCount,
                salt: Utils.stringAsArrayBuffer(decryptionParams.salt)
            },
            password,
            contentToEncrypt: encryptedDataView
        },
        cryptoWorker
    );
    const asn1Data: asn1.Asn1 = asn1.fromDer(Utils.arrayBufferAsString(decryptedData));

    return asn1Data;
}

function getDecryptionParams(oid: string, params: asn1.Asn1): DecryptionParams {
    if (oid !== pki.oids['pkcs5PBES2']) {
        throw new NotSupportedError('Cannot read encrypted PBE data block. Unsupported OID.', oid, ['pkcs5PBES2']);
    }

    return getDecryptionParamsForPBES2(oid, params);
}

function getDecryptionParamsForPBES2(oid: string, params: asn1.Asn1): DecryptionParams {
    const capture: PBES2AlgorithmsCapture = validate<PBES2AlgorithmsCapture>(params, PBES2AlgorithmsValidator);

    const keyDerivationFunctionOid: string = asn1.derToOid(util.createBuffer(capture.kdfOid));
    if (keyDerivationFunctionOid !== pki.oids['pkcs5PBKDF2']) {
        throw new NotSupportedError('Cannot read encrypted private key. Unsupported key derivation function OID.', oid, ['pkcs5PBKDF2']);
    }

    const encryptionCipherOid: string = asn1.derToOid(util.createBuffer(capture.encOid));
    if (![pki.oids['aes128-CBC'], pki.oids['aes192-CBC'], pki.oids['aes256-CBC']].includes(encryptionCipherOid)) {
        throw new NotSupportedError('Cannot read encrypted private key. Unsupported encryption scheme OID.', oid, [
            'aes128-CBC',
            'aes192-CBC',
            'aes256-CBC'
        ]);
    }

    const iterationCountBuffer: util.ByteStringBuffer = util.createBuffer(capture.kdfIterationCount);
    const iterationCount: number = iterationCountBuffer.getInt(iterationCountBuffer.length() << 3);

    const cipherName: SupportedCipher = pki.oids[encryptionCipherOid] as SupportedCipher;
    if (!['aes128-CBC', 'aes192-CBC', 'aes256-CBC'].includes(cipherName)) {
        throw new Error(`Cipher with oid ${oid} is not supported`);
    }
    const derivedKeyLengthBytes: ValidKeyByteLength = CipherByteLengthMap[cipherName];

    // get PRF message digest
    const hashAlgorithm: SupportedPrf = prfOidToHashAlgorithm(capture.prfOid);

    return { hashAlgorithm, iv: capture.encIv, derivedKeyLengthBytes, salt: capture.kdfSalt, iterationCount, cipherName };
}

function prfOidToHashAlgorithm(prfOid?: string): SupportedPrf {
    // get PRF algorithm, default to SHA-1
    if (!prfOid) {
        return 'hmacWithSHA1';
    }
    const oid: string = asn1.derToOid(util.createBuffer(prfOid));
    const prfAlgorithm: SupportedPrf = pki.oids[oid] as SupportedPrf;
    if (!prfAlgorithm) {
        throw new NotSupportedError('Unsupported PRF OID.', oid, ['hmacWithSHA1', 'hmacWithSHA256', 'hmacWithSHA384', 'hmacWithSHA512']);
    }
    return prfAlgorithm;
}

async function deriveKeyAndDecrypt(parameters: EncryptPrivateKeyParams, cryptoWorker: Crypto): Promise<ArrayBuffer> {
    let resolvedArrayBuffer: ArrayBuffer;
    try {
        const derivedKey: CryptoKey = await deriveKey(parameters, cryptoWorker);
        resolvedArrayBuffer = await getResolverArrayBuffer(parameters, cryptoWorker, derivedKey);
    } catch (e) {
        const derivedKey: CryptoKey = await deriveKey(parameters, cryptoWorker, Encoding.ISO8859);
        resolvedArrayBuffer = await getResolverArrayBuffer(parameters, cryptoWorker, derivedKey);
    }

    return resolvedArrayBuffer;
}

async function getResolverArrayBuffer(
    parameters: EncryptPrivateKeyParams,
    cryptoWorker: Crypto,
    derivedKey: CryptoKey
): Promise<ArrayBuffer> {
    return await cryptoWorker.subtle.decrypt(parameters.contentEncryptionAlgorithm, derivedKey, parameters.contentToEncrypt);
}
