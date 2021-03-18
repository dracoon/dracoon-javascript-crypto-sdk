export class GenericCryptoError extends Error {
    private static readonly description: string = 'An unexpected crypto error occured.';
    public constructor() {
        super(GenericCryptoError.description);
    }
}
