export class ValidationError extends Error {
    public constructor(message: string, public readonly reasons: readonly string[]) {
        super(message);
    }
}
