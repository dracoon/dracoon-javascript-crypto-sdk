export class NotSupportedError extends Error {
    public constructor(message: string, public readonly unsupportedOid: string, public readonly supported: readonly string[]) {
        super(`${message}\nUnsupported OID: ${unsupportedOid}\nSupported: [${supported.join(', ')}]`);
    }
}
