"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.computeAllInputs = exports.computeS = exports.computeHashToCurveR = exports.computeRPoint = exports.computeNullifer = exports.computeC_V1 = exports.computeC_V2 = exports.computeHashToCurve = exports.PlumeVersion = void 0;
var secp256k1_1 = require("@noble/secp256k1");
var encoding_1 = require("./utils/encoding");
var hashToCurve_1 = require("./utils/hashToCurve");
var curve_1 = require("./utils/curve");
var js_sha256_1 = require("js-sha256");
// PLUME version
var PlumeVersion;
(function (PlumeVersion) {
    PlumeVersion[PlumeVersion["V1"] = 1] = "V1";
    PlumeVersion[PlumeVersion["V2"] = 2] = "V2";
})(PlumeVersion || (exports.PlumeVersion = PlumeVersion = {}));
function computeHashToCurve(message, pk) {
    // Concatenate message and publicKey
    var preimage = new Uint8Array(message.length + pk.length);
    preimage.set(message);
    preimage.set(pk, message.length);
    return (0, hashToCurve_1.default)(Array.from(preimage));
}
exports.computeHashToCurve = computeHashToCurve;
function computeC_V2(nullifier, rPoint, hashedToCurveR) {
    var nullifierBytes = nullifier.toRawBytes(true);
    var preimage = (0, encoding_1.concatUint8Arrays)([
        nullifierBytes,
        rPoint.toRawBytes(true),
        hashedToCurveR.toRawBytes(true),
    ]);
    return js_sha256_1.sha256.create().update(preimage).hex();
}
exports.computeC_V2 = computeC_V2;
function computeC_V1(pkBytes, hashedToCurve, nullifier, rPoint, hashedToCurveR) {
    var nullifierBytes = nullifier.toRawBytes(true);
    var preimage = (0, encoding_1.concatUint8Arrays)([
        secp256k1_1.Point.BASE.toRawBytes(true),
        pkBytes,
        new secp256k1_1.Point((0, encoding_1.hexToBigInt)(hashedToCurve.x.toString()), (0, encoding_1.hexToBigInt)(hashedToCurve.y.toString())).toRawBytes(true),
        nullifierBytes,
        rPoint.toRawBytes(true),
        hashedToCurveR.toRawBytes(true),
    ]);
    return js_sha256_1.sha256.create().update(preimage).hex();
}
exports.computeC_V1 = computeC_V1;
function computeNullifer(hashedToCurve, sk) {
    return (0, curve_1.multiplyPoint)(hashedToCurve, sk);
}
exports.computeNullifer = computeNullifer;
function computeRPoint(rScalar) {
    return secp256k1_1.Point.fromPrivateKey(rScalar);
}
exports.computeRPoint = computeRPoint;
function computeHashToCurveR(hashedToCurve, rScalar) {
    return (0, curve_1.multiplyPoint)(hashedToCurve, rScalar);
}
exports.computeHashToCurveR = computeHashToCurveR;
function computeS(rScalar, sk, c) {
    return (((((0, encoding_1.uint8ArrayToBigInt)(sk) * (0, encoding_1.hexToBigInt)(c)) % secp256k1_1.CURVE.n) +
        (0, encoding_1.uint8ArrayToBigInt)(rScalar)) %
        secp256k1_1.CURVE.n).toString(16);
}
exports.computeS = computeS;
/**
 * Computes and returns the Plume and other signals for the prover.
 * @param {string | Uint8Array} message - Message to sign, in either string or UTF-8 array format.
 * @param {string | Uint8Array} sk - ECDSA secret key to sign with.
 * @param {string| Uint8Array} rScalar - Optional seed for randomness.
 * @returns Object containing Plume and other signals - public key, s, c, gPowR, and hashMPKPowR.
 */
function computeAllInputs(message, sk, rScalar, version) {
    if (version === void 0) { version = PlumeVersion.V2; }
    var skBytes = typeof sk === "string" ? (0, encoding_1.hexToUint8Array)(sk) : sk;
    var messageBytes = typeof message === "string" ? (0, encoding_1.messageToUint8Array)(message) : message;
    var pkBytes = (0, secp256k1_1.getPublicKey)(skBytes, true);
    var rScalarBytes;
    if (rScalar) {
        rScalarBytes =
            typeof rScalar === "string" ? (0, encoding_1.hexToUint8Array)(rScalar) : rScalar;
    }
    else {
        rScalarBytes = secp256k1_1.utils.randomPrivateKey();
    }
    var hashedToCurve = computeHashToCurve(messageBytes, pkBytes);
    var nullifier = computeNullifer(hashedToCurve, skBytes);
    var hashedToCurveR = computeHashToCurveR(hashedToCurve, rScalarBytes);
    var rPoint = computeRPoint(rScalarBytes);
    var c = version == PlumeVersion.V1
        ? computeC_V1(pkBytes, hashedToCurve, nullifier, rPoint, hashedToCurveR)
        : computeC_V2(nullifier, rPoint, hashedToCurveR);
    var s = computeS(rScalarBytes, skBytes, c);
    return {
        plume: nullifier,
        s: s,
        pk: pkBytes,
        c: c,
        rPoint: rPoint,
        hashedToCurveR: hashedToCurveR,
    };
}
exports.computeAllInputs = computeAllInputs;
