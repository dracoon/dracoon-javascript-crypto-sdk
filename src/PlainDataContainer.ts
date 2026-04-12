export class PlainDataContainer {
    private readonly content: Uint8Array<ArrayBuffer>;

    public constructor(content: Uint8Array<ArrayBuffer>) {
        this.content = content;
    }

    public getContent(): Uint8Array<ArrayBuffer> {
        return this.content;
    }
}
