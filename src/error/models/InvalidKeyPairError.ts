export class InvalidKeyPairError extends Error {
    private static readonly description: string = 'The provided key pair is invalid.';
    public constructor() {
        super(InvalidKeyPairError.description);
    }
}
