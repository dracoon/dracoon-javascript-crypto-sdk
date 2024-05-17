import { asn1, pki, util } from 'node-forge';
import { PlainUserKeyPairContainer } from '../../models/PlainUserKeyPairContainer';
import { UserKeyPairContainer } from '../../models/UserKeyPairContainer';
import { deriveKey } from './deriveKey';
import { getCryptoWorker } from '../cryptoWorker';
import { HashAlgToPrf } from './maps';
import { EncryptPrivateKeyConfig, EncryptPrivateKeyParams, SupportedPrf, ValidKeyByteLength } from './models';
import { Utils } from './utils';

declare module 'node-forge' {
    // eslint-disable-next-line @typescript-eslint/no-namespace
    namespace asn1 {
        function integerToDer(x: number): util.ByteStringBuffer;
    }
}

export async function encryptPrivateKeyAsync(
    plainUserKeyPairContainer: PlainUserKeyPairContainer,
    password: string
): Promise<UserKeyPairContainer> {
    const plainPrivateKeyPEM: pki.PEM = plainUserKeyPairContainer.privateKeyContainer.privateKey;

    const encryptedPrivateKeyPEM: pki.PEM = await encryptRsaPrivateKeyAsync(
        plainPrivateKeyPEM,
        password,
        getEncryptParams(getCryptoWorker()),
        getCryptoWorker()
    );

    const userKeyPairContainer: UserKeyPairContainer = {
        privateKeyContainer: { ...plainUserKeyPairContainer.privateKeyContainer },
        publicKeyContainer: { ...plainUserKeyPairContainer.publicKeyContainer }
    };
    userKeyPairContainer.privateKeyContainer.privateKey = encryptedPrivateKeyPEM;
    return userKeyPairContainer;
}

export function getEncryptParams(cryptoWorker: Crypto): EncryptPrivateKeyConfig {
    const options: EncryptPrivateKeyConfig = {
        encryptParams: {
            name: 'AES-CBC',
            length: 256,
            iv: new Uint8Array(16)
        },
        hashingParams: {
            iterationCount: 1.3e6,
            salt: new Uint8Array(20),
            hmacHashAlgorithm: 'SHA-1'
        }
    };
    cryptoWorker.getRandomValues(options.encryptParams.iv);
    cryptoWorker.getRandomValues(options.hashingParams.salt);
    return options;
}

/**
 * Enrypts an RSA private key
 *
 * inspired by
 * https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/lib/pbe.js#L454
 *
 * @param pem the the PEM-formatted RSA key to encrypt.
 * @param password the password to encrypt the rsa key with.
 * @param encryptionConfig the config used for key derivation and encryption.
 * @param cryptoWorker the crypto implementation that will perform key derivation and enctyption.
 * @returns the PEM-formatted encrypted RSA private key.
 */
export async function encryptRsaPrivateKeyAsync(
    pem: string,
    password: string,
    encryptionConfig: EncryptPrivateKeyConfig,
    cryptoWorker: Crypto
): Promise<string> {
    const { encryptParams: encryptConfig, hashingParams: hashingConfig } = encryptionConfig;

    const contentToEncrypt: Uint8Array = Utils.stringAsArrayBuffer(
        asn1.toDer(pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(pki.privateKeyFromPem(pem)))).getBytes()
    );

    const encryptedData: ArrayBuffer = await deriveKeyAndEncrypt(
        {
            password,
            contentToEncrypt,
            contentEncryptionAlgorithm: encryptConfig,
            hashingParams: hashingConfig
        },
        cryptoWorker
    );

    const encryptionKeyBytes: ValidKeyByteLength = (encryptConfig.length / 8) as ValidKeyByteLength;
    const encOid: string = pki.oids[`aes${encryptConfig.length}-CBC`];

    return buildPEM(encryptionConfig, encryptionKeyBytes, encOid, encryptedData);
}

async function deriveKeyAndEncrypt(parameters: EncryptPrivateKeyParams, cryptoWorker: Crypto): Promise<ArrayBuffer> {
    const derivedKey: CryptoKey = await deriveKey(parameters, cryptoWorker);
    return cryptoWorker.subtle.encrypt(parameters.contentEncryptionAlgorithm, derivedKey, parameters.contentToEncrypt);
}

function buildPEM(
    { encryptParams, hashingParams }: EncryptPrivateKeyConfig,
    encryptionKeyBytes: number,
    encOid: string,
    encryptedData: ArrayBuffer
): pki.PEM {
    const pbkdf2Params: Pbkdf2ParamsAsn1 = createPbkdf2Params(
        Utils.arrayBufferAsString(hashingParams.salt),
        asn1.integerToDer(hashingParams.iterationCount),
        encryptionKeyBytes,
        HashAlgToPrf[hashingParams.hmacHashAlgorithm]
    );
    const encryptionAlgorithm: AlgorithmAsn1 = createAlgorithmAsn(pbkdf2Params, encOid, encryptParams.iv);
    const encryptedPrivateKeyInfo: EncryptedPrivateKeyInfoAsn1 = createEncryptedPrivateKeyInfoAsn1(encryptionAlgorithm, encryptedData);

    return pki.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo);
}

type Pbkdf2ParamsAsn1 = asn1.Asn1 & { __declared_type__: 'Pbkdf2ParamsAsn1' };
function createPbkdf2Params(
    salt: string,
    countBytes: util.ByteStringBuffer,
    encryptionKeyByteLength: number,
    prfAlgorithm: SupportedPrf
): Pbkdf2ParamsAsn1 {
    const params: Pbkdf2ParamsAsn1 = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // salt
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, salt),
        // iteration count
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, countBytes.getBytes())
    ]) as Pbkdf2ParamsAsn1;

    if (prfAlgorithm === 'hmacWithSHA1') {
        return params;
    }

    // when PRF algorithm is not SHA-1 default, add key length and PRF algorithm
    (params.value as asn1.Asn1[]).push(
        // key length
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, util.hexToBytes(encryptionKeyByteLength.toString(16))),
        // AlgorithmIdentifier
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // algorithm
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(pki.oids[prfAlgorithm]).getBytes()),
            // parameters (null)
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
        ])
    );

    return params;
}

type AlgorithmAsn1 = asn1.Asn1 & { __declared_type__: 'AlgorithmAsn1' };
function createAlgorithmAsn(params: Pbkdf2ParamsAsn1, encOid: string, iv: Uint8Array): AlgorithmAsn1 {
    return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(pki.oids['pkcs5PBES2']).getBytes()),
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // keyDerivationFunc
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(pki.oids['pkcs5PBKDF2']).getBytes()),
                // PBKDF2-params
                params
            ]),
            // encryptionScheme
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(encOid).getBytes()),
                // iv
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, Utils.arrayBufferAsString(iv))
            ])
        ])
    ]) as AlgorithmAsn1;
}

type EncryptedPrivateKeyInfoAsn1 = asn1.Asn1 & { __declared_type__: 'EncryptedPrivateKeyInfoAsn1' };
function createEncryptedPrivateKeyInfoAsn1(encryptionAlgorithm: AlgorithmAsn1, encryptedData: ArrayBuffer): EncryptedPrivateKeyInfoAsn1 {
    return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // encryptionAlgorithm
        encryptionAlgorithm,
        // encryptedData
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, Utils.arrayBufferAsString(encryptedData))
    ]) as EncryptedPrivateKeyInfoAsn1;
}
