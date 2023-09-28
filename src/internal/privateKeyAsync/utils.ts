export function arrayBufferAsString(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer), (x) => String.fromCharCode(x)).join('');
}

export function stringAsArrayBuffer(str: string): Uint8Array {
    return new Uint8Array([...str].map((c) => c.charCodeAt(0)));
}
