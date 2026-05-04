pragma circom 2.2.2;

include "../shared/components/aesGcm/ctrDecrypt.circom";
include "../shared/components/deserialization.circom";
include "../shared/components/bus.circom";

template CreateWill(keyBits, ciphertextBytes) {
    var Nk;
    assert(keyBits == 128 || keyBits == 192 || keyBits == 256);
    if (keyBits == 128) {
        Nk = 4;
    } else if (keyBits == 192) {
        Nk = 6;
    } else {
        Nk = 8;
    }

    var numEstates = calNumEstates(ciphertextBytes);

    signal input {byte} iv[16];
    signal input {byte} ciphertext[ciphertextBytes];
    input Word() key[Nk];
    signal output {address} testator;
    signal output {address} executor;
    output Estate() estates[numEstates];
    signal output {uint256} salt[4];

    // decryption
    var plaintextBytes = ciphertextBytes;
    signal {byte} plaintext[plaintextBytes] <== CtrDecrypt(keyBits, ciphertextBytes)(ciphertext, key, iv);
    
    // deserialization
    (testator, executor, estates, salt, _, _, _, _) <== Deserialize(plaintextBytes)(plaintext);
}

// Auto updated: 2025-10-22T23:56:10.832Z
bus UntaggedWord() {
    signal bytes[4];
}

bus UntaggedEstate() {
    signal beneficiary;
    signal token;
    signal amount;
}

template UntaggedCreateWill(keyBits, ciphertextBytes) {
    var Nk;
    assert(keyBits == 128 || keyBits == 192 || keyBits == 256);
    if (keyBits == 128) {
        Nk = 4;
    } else if (keyBits == 192) {
        Nk = 6;
    } else {
        Nk = 8;
    }
    var numEstates = calNumEstates(ciphertextBytes);

    signal input iv[16];
    signal input ciphertext[ciphertextBytes];
    input UntaggedWord() key[Nk];
    signal output {address} testator;
    signal output {address} executor;
    output Estate() estates[numEstates];
    signal output {uint256} salt[4];

    signal {byte} _iv[16];
    _iv <== iv;
    signal {byte} _ciphertext[ciphertextBytes];
    _ciphertext <== ciphertext;

    Word() _key[Nk];

    for (var i = 0; i < Nk; i++) {
        _key[i].bytes <== key[i].bytes;
    }


    component createwillComponent = CreateWill(keyBits, ciphertextBytes);
    createwillComponent.iv <== _iv;
    createwillComponent.ciphertext <== _ciphertext;
    createwillComponent.key <== _key;
    testator <== createwillComponent.testator;
    executor <== createwillComponent.executor;
    estates <== createwillComponent.estates;
    salt <== createwillComponent.salt;
}

component main {public [iv, ciphertext]} = UntaggedCreateWill(256, 293);