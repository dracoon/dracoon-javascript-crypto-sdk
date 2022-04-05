export class PlainDataContainer {
    private readonly content: Uint8Array;

    public constructor(content: Uint8Array) {
        this.content = content;
    }

    public getContent(): Uint8Array {
        return this.content;
    }
}
