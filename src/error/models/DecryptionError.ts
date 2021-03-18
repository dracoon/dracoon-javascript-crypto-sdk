export class DecryptionError extends Error {
    private static readonly description: string = 'The decryption was not possible.';
    public constructor() {
        super(DecryptionError.description);
    }
}
