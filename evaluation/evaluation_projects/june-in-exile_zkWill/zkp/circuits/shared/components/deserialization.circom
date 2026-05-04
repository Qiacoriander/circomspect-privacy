pragma circom 2.2.2;

include "bits.circom";
include "bus.circom";

function calNumEstates(bytesLength) {
    var testatorBytesLength = 20;
    var executorBytesLength = 20;
    var beneficiaryBytesLength = 20;
    var tokenBytesLength = 20;
    var amountBytesLength = 16;
    var saltBytesLength = 32;
    var willBytesLength = 20;
    var nonceBytesLength = 16;
    var deadlineBytesLength = 8;
    var signatureBytesLength = 65;
    var totalEstatesLength = bytesLength - (testatorBytesLength + executorBytesLength + saltBytesLength + willBytesLength + nonceBytesLength + deadlineBytesLength + signatureBytesLength);
    var perEstateLength = beneficiaryBytesLength + tokenBytesLength + amountBytesLength;
    assert (perEstateLength == 56 && totalEstatesLength % perEstateLength == 0);

    var numEstates = totalEstatesLength \ perEstateLength;

    return numEstates;
}

/**
 * Deserialize circuit that converts serialized byte data into structured will components.
 * Takes serialized bytes containing testator address, estates (beneficiary, token, amount), 
 * salt, will address, nonce, deadline, and signature.
 *
 * @param bytesLength - the number of bytes in serialized input
 */
template Deserialize(bytesLength) {
    var numEstates = calNumEstates(bytesLength);

    signal input {byte} serializedBytes[bytesLength];
    signal output {address} testator;       // 20-byte unsigned integer
    signal output {address} executor;       // 20-byte unsigned integer
    output Estate() estates[numEstates];
    signal output {uint256} salt[4];        // 32-byte unsigned integer composed of 4 8-byte registers, little-endian
    signal output {address} will;           // 20-byte unsigned integer
    signal output {uint128} nonce;          // 16-byte unsigned integer
    signal output {uint32} deadline;        //  4-byte unsigned integer
    output EcdsaSignature() signature;

    var testatorBytesLength = 20;
    var executorBytesLength = 20;
    var beneficiaryBytesLength = 20;
    var tokenBytesLength = 20;
    var amountBytesLength = 16;
    var saltBytesLength = 32;
    var willBytesLength = 20;
    var nonceBytesLength = 16;
    var deadlineBytesLength = 8;
    var signatureBytesLength = 65;

    signal {byte} testatorBytes[testatorBytesLength];
    signal {byte} executorBytes[executorBytesLength];
    signal {byte} beneficiaryBytes[numEstates][beneficiaryBytesLength];
    signal {byte} tokenBytes[numEstates][tokenBytesLength];
    signal {byte} amountBytes[numEstates][amountBytesLength];
    signal {byte} saltBytes[4][saltBytesLength\4];
    signal {byte} willBytes[willBytesLength];
    signal {byte} nonceBytes[nonceBytesLength];
    signal {byte} deadlineBytes[deadlineBytesLength];
    signal {byte} rBytes[4][8];
    signal {byte} sBytes[4][8];

    var byteIdx = 0;

    // process testator
    for (var i = 0; i < testatorBytesLength; i++) {
        testatorBytes[i] <== serializedBytes[byteIdx];
        byteIdx++;
    }    
    testator <== BytesToNum(testatorBytesLength, 0)(testatorBytes);

    // process executor
    for (var i = 0; i < executorBytesLength; i++) {
        executorBytes[i] <== serializedBytes[byteIdx];
        byteIdx++;
    }    
    executor <== BytesToNum(executorBytesLength, 0)(executorBytes);

    // process estates
    for (var estateIdx = 0; estateIdx < numEstates; estateIdx++) {
        // process beneficiary
        for (var i = 0; i < beneficiaryBytesLength; i++) {
            beneficiaryBytes[estateIdx][i] <== serializedBytes[byteIdx];
            byteIdx++;
        }
        estates[estateIdx].beneficiary <== BytesToNum(beneficiaryBytesLength, 0)(beneficiaryBytes[estateIdx]);

        // process token
        for (var i = 0; i < tokenBytesLength; i++) {
            tokenBytes[estateIdx][i] <== serializedBytes[byteIdx];
            byteIdx++;
        }
        estates[estateIdx].token <== BytesToNum(tokenBytesLength, 0)(tokenBytes[estateIdx]);

        // process amount
        for (var i = 0; i < amountBytesLength; i++) {
            amountBytes[estateIdx][i] <== serializedBytes[byteIdx];
            byteIdx++;
        }
        estates[estateIdx].amount <== BytesToNum(amountBytesLength, 0)(amountBytes[estateIdx]);
    }

    // process salt
    var quarterSaltBytesLength = saltBytesLength \ 4;
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < quarterSaltBytesLength; j++) {
            saltBytes[3 - i][j] <== serializedBytes[byteIdx];
            byteIdx++;
        }
        salt[3 - i] <== BytesToNum(quarterSaltBytesLength, 0)(saltBytes[3 - i]);
    }

    // process will
    for (var i = 0; i < willBytesLength; i++) {
        willBytes[i] <== serializedBytes[byteIdx];
        byteIdx++;
    }
    will <== BytesToNum(willBytesLength, 0)(willBytes);

    // process nonce
    for (var i = 0; i < nonceBytesLength; i++) {
        nonceBytes[i] <== serializedBytes[byteIdx];
        byteIdx++;
    }
    nonce <== BytesToNum(nonceBytesLength, 0)(nonceBytes);

    // process deadline
    for (var i = 0; i < deadlineBytesLength; i++) {
        deadlineBytes[i] <== serializedBytes[byteIdx];
        byteIdx++;
    }
    deadline <== BytesToNum(deadlineBytesLength, 0)(deadlineBytes);

    // process signature r
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 8; j++) {
            rBytes[3 - i][j] <== serializedBytes[byteIdx];
            byteIdx++;
        }
        signature.r[3 - i] <== BytesToNum(8, 0)(rBytes[3 - i]);
    }

    // process signature s
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 8; j++) {
            sBytes[3 - i][j] <== serializedBytes[byteIdx];
            byteIdx++;
        }
        signature.s[3 - i] <== BytesToNum(8, 0)(sBytes[3 - i]);
    }

    // process signature v
    signature.v <== serializedBytes[byteIdx];
}