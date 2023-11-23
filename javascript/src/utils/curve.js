"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.multiplyPoint = void 0;
var secp256k1_1 = require("@noble/secp256k1");
var encoding_1 = require("./encoding");
function multiplyPoint(h, secretKey) {
    var hashPoint = new secp256k1_1.Point(BigInt("0x" + h.x.toString()), BigInt("0x" + h.y.toString()));
    return hashPoint.multiply(BigInt("0x" + (0, encoding_1.uint8ArrayToHex)(secretKey)));
}
exports.multiplyPoint = multiplyPoint;
