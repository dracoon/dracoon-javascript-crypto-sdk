const UNKNOWN_CHAR = 0x3f;
const ISO_MAX_RANGE = 0xff;

export class Utils {
    public static arrayBufferAsString(buffer: ArrayBuffer): string {
        return Array.from(new Uint8Array(buffer), (x) => String.fromCharCode(x)).join('');
    }

    public static stringAsArrayBuffer(str: string): Uint8Array {
        return new Uint8Array([...str].map((c) => c.charCodeAt(0)));
    }

    public static encodeISO(password: string): Uint8Array {
        const byteArray: number[] = [];
        for (let i = 0; i < password.length; i++) {
            const charCode = password.charCodeAt(i);
            //check if character is a high surrogate
            if (charCode >= 0xd800 && charCode <= 0xdbff) {
                const nextCharCode = password.charCodeAt(i + 1);
                //check if the next character is a low surrogate
                if (nextCharCode >= 0xdc00 && nextCharCode <= 0xdfff) {
                    i++; // Skip the next character as it is part of the surrogate pair
                    byteArray.push(UNKNOWN_CHAR); // Replace the entire surrogate pair with a single '?'
                    continue;
                }
            }
            if (charCode > ISO_MAX_RANGE) {
                byteArray.push(UNKNOWN_CHAR); //Replace character with '?' if it is not in the ISO-8859-1 range
            }
            if (charCode <= ISO_MAX_RANGE) {
                byteArray.push(charCode); //Push the corresponding character code into the array
            }
        }
        return new Uint8Array(byteArray);
    }
}
