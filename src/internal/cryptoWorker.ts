let cryptoWorker: Crypto;

export function getCryptoWorker(): Crypto {
    return cryptoWorker;
}

export function setCryptoWorker(_cryptoWorker: Crypto): void {
    cryptoWorker = _cryptoWorker;
}
