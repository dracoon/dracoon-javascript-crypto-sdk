export class InvalidArgumentError extends Error {
    private static readonly description: string = 'A falsy value has been provided for a required argument.';
    public constructor() {
        super(InvalidArgumentError.description);
    }
}
