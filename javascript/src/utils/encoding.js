"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.concatUint8Arrays = exports.asciitobytes = exports.uint8ArrayToBigInt = exports.hexToBigInt = exports.uint8ArrayToHex = exports.hexToUint8Array = exports.messageToUint8Array = void 0;
var utf8Encoder = new TextEncoder();
function messageToUint8Array(message) {
    return utf8Encoder.encode(message);
}
exports.messageToUint8Array = messageToUint8Array;
function hexToUint8Array(hexString) {
    // Source: https://stackoverflow.com/questions/38987784/how-to-convert-a-hexadecimal-string-to-uint8array-and-back-in-javascript/50868276#50868276
    return Uint8Array.from(hexString.match(/.{1,2}/g).map(function (byte) { return parseInt(byte, 16); }));
}
exports.hexToUint8Array = hexToUint8Array;
function uint8ArrayToHex(uint8Array) {
    // Source: https://stackoverflow.com/questions/38987784/how-to-convert-a-hexadecimal-string-to-uint8array-and-back-in-javascript/50868276#50868276
    return uint8Array.reduce(function (str, byte) { return str + byte.toString(16).padStart(2, "0"); }, "");
}
exports.uint8ArrayToHex = uint8ArrayToHex;
function hexToBigInt(hex) {
    return BigInt("0x" + hex);
}
exports.hexToBigInt = hexToBigInt;
function uint8ArrayToBigInt(buffer) {
    return hexToBigInt(uint8ArrayToHex(buffer));
}
exports.uint8ArrayToBigInt = uint8ArrayToBigInt;
function asciitobytes(s) {
    var b = [];
    for (var i = 0; i < s.length; i++) {
        b.push(s.charCodeAt(i));
    }
    return b;
}
exports.asciitobytes = asciitobytes;
function concatUint8Arrays(arrays) {
    // sum of individual array lengths
    var totalLength = arrays.reduce(function (acc, value) { return acc + value.length; }, 0);
    var result = new Uint8Array(totalLength);
    if (!arrays.length) {
        return result;
    }
    // for each array - copy it over result
    // next array is copied right after the previous one
    var length = 0;
    for (var _i = 0, arrays_1 = arrays; _i < arrays_1.length; _i++) {
        var array = arrays_1[_i];
        result.set(array, length);
        length += array.length;
    }
    return result;
}
exports.concatUint8Arrays = concatUint8Arrays;
