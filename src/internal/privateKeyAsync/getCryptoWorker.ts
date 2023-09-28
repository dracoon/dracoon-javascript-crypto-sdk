export const getCryptoWorker: () => Crypto = ((): (() => Crypto) => {
    let cryptoWorker: Crypto;

    const _getCryptoWorker = (): Crypto => {
        if (globalThis.crypto !== undefined) {
            return crypto;
        }

        // eslint-disable-next-line @typescript-eslint/no-var-requires
        return (require('node:crypto') as { webcrypto: Crypto }).webcrypto;
    };

    return () => {
        if (!cryptoWorker) {
            cryptoWorker = _getCryptoWorker();
        }
        return cryptoWorker;
    };
})();
