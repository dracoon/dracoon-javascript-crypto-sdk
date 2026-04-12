import { Base64 } from 'node-forge';

export class EncryptedDataContainer {
    private readonly content: Uint8Array<ArrayBuffer>;
    private readonly tag: Base64 | undefined;

    public constructor(content: Uint8Array<ArrayBuffer>, tag?: Base64) {
        this.content = content;
        this.tag = tag;
    }

    public getContent(): Uint8Array<ArrayBuffer> {
        return this.content;
    }

    public getTag(): Base64 | undefined {
        return this.tag;
    }
}
