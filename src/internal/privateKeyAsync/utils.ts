import { InvalidCharacterError } from '../../error/models/InvalidCharacterError';

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
            if (charCode > ISO_MAX_RANGE) {
                throw new InvalidCharacterError(); //If character code isn't in the specified range throw InvalidCharacterError
            }
            if (charCode <= ISO_MAX_RANGE) {
                byteArray.push(charCode); //Push the corresponding character code into the array
            }
        }
        return new Uint8Array(byteArray);
    }
}
