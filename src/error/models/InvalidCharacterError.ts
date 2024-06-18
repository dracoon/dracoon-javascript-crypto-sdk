export class InvalidCharacterError extends Error {
    private static readonly description: string = 'The password contains illegal characters.';
    public constructor() {
        super(InvalidCharacterError.description);
    }
}
