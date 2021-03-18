export class InvalidFileKeyError extends Error {
    private static readonly description: string = 'The provided file key is invalid.';
    public constructor() {
        super(InvalidFileKeyError.description);
    }
}
