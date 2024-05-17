import { Utils } from '../../src/internal/privateKeyAsync/utils';

describe('Class: Utils', () => {
    describe('Function: arrayBufferAsString', () => {
        test.each([
            { input: new Uint8Array([83, 111, 109, 101, 80, 97, 115, 115, 119, 111, 114, 100]).buffer, output: 'SomePassword' },
            { input: new Uint8Array([169]).buffer, output: '©' }
        ])('should convert the given ArrayBuffer to the correct string', ({ input, output }) => {
            expect(Utils.arrayBufferAsString(input)).toEqual(output);
        });
    });
    describe('Function: stringAsArrayBuffer', () => {
        test.each([
            { input: 'someString', output: new Uint8Array([115, 111, 109, 101, 83, 116, 114, 105, 110, 103]) },
            { input: '#@äfjiFUbFdN', output: new Uint8Array([35, 64, 228, 102, 106, 105, 70, 85, 98, 70, 100, 78]) }
        ])('should convert the given string to the correct Uint8Array', ({ input, output }) => {
            expect(Utils.stringAsArrayBuffer(input)).toEqual(output);
        });
    });

    describe('Function: encodeISO', () => {
        //the expected output got generated with String.getBytes(ISO-8859-1) in Java
        describe('when encoding a password with the fallback encoding ISO-8859-1', () => {
            test.each([
                { password: 'SomePassword', expected: new Uint8Array([83, 111, 109, 101, 80, 97, 115, 115, 119, 111, 114, 100]) },
                {
                    password: 'SomePassword!ä',
                    expected: new Uint8Array([83, 111, 109, 101, 80, 97, 115, 115, 119, 111, 114, 100, 33, 228])
                },
                { password: '🇩🇪', expected: new Uint8Array([63, 63]) },
                { password: '🇩', expected: new Uint8Array([63]) },
                { password: '🚕🚀', expected: new Uint8Array([63, 63]) },
                { password: '😡#@äfjiFUbFdN🚨', expected: new Uint8Array([63, 35, 64, 228, 102, 106, 105, 70, 85, 98, 70, 100, 78, 63]) },
                { password: '©', expected: new Uint8Array([169]) }
            ])('should convert $password to the correct byteArray $expected', ({ password, expected }) => {
                expect(Utils.encodeISO(password)).toEqual(expected);
            });
        });
    });
});
