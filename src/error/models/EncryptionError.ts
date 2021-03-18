export class EncryptionError extends Error {
    private static readonly description: string = 'The encryption was not possible.';
    public constructor() {
        super(EncryptionError.description);
    }
}
