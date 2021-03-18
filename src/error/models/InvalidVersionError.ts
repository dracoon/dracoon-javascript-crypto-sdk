export class InvalidVersionError extends Error {
    private static readonly description: string = 'The provided version is not supported.';
    public constructor() {
        super(InvalidVersionError.description);
    }
}
