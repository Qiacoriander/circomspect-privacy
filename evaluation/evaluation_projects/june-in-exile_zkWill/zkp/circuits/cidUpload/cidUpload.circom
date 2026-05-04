pragma circom 2.2.2;

include "../shared/components/aesGcm/ctrDecrypt.circom";
include "../shared/components/permitVerify/permitVerify.circom";
include "../shared/components/deserialization.circom";
include "../shared/components/bus.circom";

template UploadCid(keyBits, ciphertextBytes) {
    var Nk;
    assert(keyBits == 128 || keyBits == 192 || keyBits == 256);
    if (keyBits == 128) {
        Nk = 4;
    } else if (keyBits == 192) {
        Nk = 6;
    } else {
        Nk = 8;
    }

    signal input {byte} iv[16];
    signal input {byte} ciphertext[ciphertextBytes];
    input Word() key[Nk];
    signal output {address} testator;

    // decryption
    var plaintextBytes = ciphertextBytes;
    signal {byte} plaintext[plaintextBytes] <== CtrDecrypt(keyBits, ciphertextBytes)(ciphertext, key, iv);
    
    // deserialization
    var numEstates = calNumEstates(plaintextBytes);
    Estate() estates[numEstates];
    signal {address} will;
    signal {uint128} nonce;
    signal {uint32} deadline;
    EcdsaSignature() signature;
    (testator, _, estates, _, will, nonce, deadline, signature) <== Deserialize(plaintextBytes)(plaintext);

    // verification
    var numPermission = numEstates;
    PermitBatchTransferFrom(numPermission) permit;
    for (var i = 0; i < numPermission; i++) {
        permit.permitted[i].token <== estates[i].token;
        permit.permitted[i].amount <== estates[i].amount;
    }
    permit.nonce <== nonce;
    permit.deadline <== deadline;
    VerifyPermit(numPermission)(testator, permit, will, signature);
}

// Auto updated: 2025-10-22T20:12:31.487Z
bus UntaggedWord() {
    signal bytes[4];
}

template UntaggedUploadCid(keyBits, ciphertextBytes) {
    var Nk;
    assert(keyBits == 128 || keyBits == 192 || keyBits == 256);
    if (keyBits == 128) {
        Nk = 4;
    } else if (keyBits == 192) {
        Nk = 6;
    } else {
        Nk = 8;
    }

    signal input iv[16];
    signal input ciphertext[ciphertextBytes];
    input UntaggedWord() key[Nk];
    signal output {address} testator;

    signal {byte} _iv[16];
    _iv <== iv;
    signal {byte} _ciphertext[ciphertextBytes];
    _ciphertext <== ciphertext;

    Word() _key[Nk];

    for (var i = 0; i < Nk; i++) {
        _key[i].bytes <== key[i].bytes;
    }


    component uploadcidComponent = UploadCid(keyBits, ciphertextBytes);
    uploadcidComponent.iv <== _iv;
    uploadcidComponent.ciphertext <== _ciphertext;
    uploadcidComponent.key <== _key;
    testator <== uploadcidComponent.testator;
}

component main {public [iv, ciphertext]} = UntaggedUploadCid(256, 293);
