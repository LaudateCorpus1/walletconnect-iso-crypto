"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const isoCrypto = tslib_1.__importStar(require("@pedrouid/iso-crypto"));
const encUtils = tslib_1.__importStar(require("enc-utils"));
const utils_1 = require("@walletconnect/utils");

import BlocksoftCryptoLog from '@crypto/common/BlocksoftCryptoLog'

function generateKey(length) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        BlocksoftCryptoLog.log('@walletconnect/iso-crypto generateKey start')
        const _length = (length || 256) / 8;
        const bytes = Buffer.from(yield require('crypto').randomBytes(_length), 'base64');
        const result = utils_1.convertBufferToArrayBuffer(encUtils.arrayToBuffer(bytes));
        return result;
    });
}
exports.generateKey = generateKey;

function isUpdated(length) {
    return 'isUpdated'
}
exports.isUpdated = isUpdated;

function verifyHmac(payload, key) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const cipherText = encUtils.hexToArray(payload.data);
        const iv = encUtils.hexToArray(payload.iv);
        const hmac = encUtils.hexToArray(payload.hmac);
        const hmacHex = encUtils.arrayToHex(hmac, false);
        const unsigned = encUtils.concatArrays(cipherText, iv);
        const chmac = yield isoCrypto.hmacSha256Sign(key, unsigned);
        const chmacHex = encUtils.arrayToHex(chmac, false);
        if (encUtils.removeHexPrefix(hmacHex) === encUtils.removeHexPrefix(chmacHex)) {
            return true;
        }
        return false;
    });
}
exports.verifyHmac = verifyHmac;
function encrypt(data, key, providedIv) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        try {
            const _key = encUtils.bufferToArray(utils_1.convertArrayBufferToBuffer(key));
            const ivArrayBuffer = providedIv || (yield generateKey(128));
            const iv = encUtils.bufferToArray(utils_1.convertArrayBufferToBuffer(ivArrayBuffer));
            const ivHex = encUtils.arrayToHex(iv, false);
            const contentString = JSON.stringify(data);
            const content = encUtils.utf8ToArray(contentString);
            const cipherText = yield isoCrypto.aesCbcEncrypt(iv, _key, content);
            const cipherTextHex = encUtils.arrayToHex(cipherText, false);
            const unsigned = encUtils.concatArrays(cipherText, iv);
            const hmac = yield isoCrypto.hmacSha256Sign(_key, unsigned);
            const hmacHex = encUtils.arrayToHex(hmac, false);
            return {
                data: cipherTextHex,
                hmac: hmacHex,
                iv: ivHex,
            };
        } catch (e) {
            BlocksoftCryptoLog.log('@walletconnect/iso-crypto encrypt error ' + e.message)
            throw e
        }
    });
}
exports.encrypt = encrypt;
function decrypt(payload, key) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const _key = encUtils.bufferToArray(utils_1.convertArrayBufferToBuffer(key));
        if (!_key) {
            BlocksoftCryptoLog.log('@walletconnect/iso-crypto decrypt error Missing key: required for decryption')
            throw new Error("Missing key: required for decryption");
        }
        const verified = yield verifyHmac(payload, _key);
        if (!verified) {
            BlocksoftCryptoLog.log('@walletconnect/iso-crypto decrypt error Not verified')
            return null;
        }
        try {
            const cipherText = encUtils.hexToArray(payload.data);
            const iv = encUtils.hexToArray(payload.iv);
            const buffer = yield isoCrypto.aesCbcDecrypt(iv, _key, cipherText);
            const utf8 = encUtils.arrayToUtf8(buffer);

            let data;
            try {
                data = JSON.parse(utf8);
            } catch (error) {
                BlocksoftCryptoLog.log('@walletconnect/iso-crypto decrypt error JSON.parse')
                return null;
            }
            return data;
        } catch (e) {
            BlocksoftCryptoLog.log('@walletconnect/iso-crypto decrypt error ' + e.message)
            throw e
        }
    });
}
exports.decrypt = decrypt;
//# sourceMappingURL=index.js.map
