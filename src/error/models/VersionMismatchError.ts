export class VersionMismatchError extends Error {
    private static readonly description: string = 'The provided versions for key pair and file key do not match.';
    public constructor() {
        super(VersionMismatchError.description);
    }
}
