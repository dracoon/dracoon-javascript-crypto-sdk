import { Base64 } from 'node-forge';

export class EncryptedDataContainer {
    private content: Uint8Array;
    private tag: Base64 | undefined;

    public constructor(content: Uint8Array, tag?: Base64) {
        this.content = content;
        this.tag = tag;
    }

    public getContent(): Uint8Array {
        return this.content;
    }

    public getTag(): Base64 | undefined {
        return this.tag;
    }
}
