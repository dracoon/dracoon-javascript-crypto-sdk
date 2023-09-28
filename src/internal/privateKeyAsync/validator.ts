import { asn1 } from 'node-forge';
import { ValidationError } from '../../error/models/ValidationError';

declare module 'node-forge' {
    // eslint-disable-next-line @typescript-eslint/no-namespace
    namespace asn1 {
        function validate(asn1: asn1.Asn1, validator: Validator, capture: Record<string, unknown>, errors: string[]): boolean;
    }
}

export function validate<T extends Record<string, unknown>>(asn1Value: asn1.Asn1, validator: Validator): T {
    const errors: string[] = [];
    const capture: T = {} as T;
    const success = asn1.validate(asn1Value, validator, capture, errors);
    if (!success) {
        throw new ValidationError(`Validation failed. ASN.1 object is not a valid ${validator.name}`, errors);
    }
    return capture;
}

type Validator = {
    name: string;
    tagClass: asn1.Class;
    type: asn1.Type;
    constructed: boolean;
    capture?: string;
    captureAsn1?: string;
    optional?: boolean;
    value?: readonly Validator[];
};

export type EncryptedPrivateKeyCapture = {
    encryptionOid: string;
    encryptionParams: asn1.Asn1;
    encryptedData: string;
};
/**
 * validator for an EncryptedPrivateKeyInfo structure
 *
 * Note: Currently only works w/algorithm params
 * @see EncryptedPrivateKeyCapture
 */
export const encryptedPrivateKeyValidator: Validator = {
    name: 'EncryptedPrivateKeyInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
        {
            name: 'EncryptedPrivateKeyInfo.encryptionAlgorithm',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.SEQUENCE,
            constructed: true,
            value: [
                {
                    name: 'AlgorithmIdentifier.algorithm',
                    tagClass: asn1.Class.UNIVERSAL,
                    type: asn1.Type.OID,
                    constructed: false,
                    capture: 'encryptionOid'
                },
                {
                    name: 'AlgorithmIdentifier.parameters',
                    tagClass: asn1.Class.UNIVERSAL,
                    type: asn1.Type.SEQUENCE,
                    constructed: true,
                    captureAsn1: 'encryptionParams'
                }
            ]
        },
        {
            // encryptedData
            name: 'EncryptedPrivateKeyInfo.encryptedData',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OCTETSTRING,
            constructed: false,
            capture: 'encryptedData'
        }
    ]
} as const;

export type PBES2AlgorithmsCapture = {
    kdfOid: string;
    kdfSalt: string;
    kdfIterationCount: string;
    prfOid?: string;
    encOid: string;
    encIv: string;
};

/**
 *  validator for a PBES2Algorithms structure
 *
 * Note: Currently only works w/PBKDF2 + AES encryption schemes
 */
export const PBES2AlgorithmsValidator: Validator = {
    name: 'PBES2Algorithms',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [
        {
            name: 'PBES2Algorithms.keyDerivationFunc',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.SEQUENCE,
            constructed: true,
            value: [
                {
                    name: 'PBES2Algorithms.keyDerivationFunc.oid',
                    tagClass: asn1.Class.UNIVERSAL,
                    type: asn1.Type.OID,
                    constructed: false,
                    capture: 'kdfOid'
                },
                {
                    name: 'PBES2Algorithms.params',
                    tagClass: asn1.Class.UNIVERSAL,
                    type: asn1.Type.SEQUENCE,
                    constructed: true,
                    value: [
                        {
                            name: 'PBES2Algorithms.params.salt',
                            tagClass: asn1.Class.UNIVERSAL,
                            type: asn1.Type.OCTETSTRING,
                            constructed: false,
                            capture: 'kdfSalt'
                        },
                        {
                            name: 'PBES2Algorithms.params.iterationCount',
                            tagClass: asn1.Class.UNIVERSAL,
                            type: asn1.Type.INTEGER,
                            constructed: false,
                            capture: 'kdfIterationCount'
                        },
                        {
                            name: 'PBES2Algorithms.params.keyLength',
                            tagClass: asn1.Class.UNIVERSAL,
                            type: asn1.Type.INTEGER,
                            constructed: false,
                            optional: true
                        },
                        {
                            // prf
                            name: 'PBES2Algorithms.params.prf',
                            tagClass: asn1.Class.UNIVERSAL,
                            type: asn1.Type.SEQUENCE,
                            constructed: true,
                            optional: true,
                            value: [
                                {
                                    name: 'PBES2Algorithms.params.prf.algorithm',
                                    tagClass: asn1.Class.UNIVERSAL,
                                    type: asn1.Type.OID,
                                    constructed: false,
                                    capture: 'prfOid'
                                }
                            ]
                        }
                    ]
                }
            ]
        },
        {
            name: 'PBES2Algorithms.encryptionScheme',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.SEQUENCE,
            constructed: true,
            value: [
                {
                    name: 'PBES2Algorithms.encryptionScheme.oid',
                    tagClass: asn1.Class.UNIVERSAL,
                    type: asn1.Type.OID,
                    constructed: false,
                    capture: 'encOid'
                },
                {
                    name: 'PBES2Algorithms.encryptionScheme.iv',
                    tagClass: asn1.Class.UNIVERSAL,
                    type: asn1.Type.OCTETSTRING,
                    constructed: false,
                    capture: 'encIv'
                }
            ]
        }
    ]
} as const;
