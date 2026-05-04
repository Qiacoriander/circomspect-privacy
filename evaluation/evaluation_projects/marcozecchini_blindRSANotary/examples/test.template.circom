pragma circom 2.0.3;

include "hash_and_blind.circom";
include "aes/ctr.circom";
/**
 * Combines SHA-256 hashing of an input byte sequence with RSA-PSS blinding.
 * @param messageLen  The length of the input message in bytes.
 */
template TLSBlind(w, k, eBits, mgfCount, signedAttrLen, messageLen, nk) {

    var bpl = w / 8; // bits per limb, es if w=64, bpl=8
    var emBytes = k * bpl; // total bytes in the encoded message, es if k=64, bpl=8, emBytes=512
    var digest_offset = 45; // offset in signed_attrs where the SHA-256 digest will be stored

    // Inputs
    signal input message[messageLen];    // message to hash
    signal input signed_attrs[signedAttrLen];  // DER of the PDF signed attributes
    signal input salt[k];               // PSS salt
    signal input r[k];                  // blinding factor (bigint limbs)
    signal input exp[k];                // public exponent (bigint limbs)
    signal input modulus[k];            // RSA modulus (bigint limbs)
    signal input iv[16];                // AES CTR IV
    signal input key[nk * 4];           // AES key (nk * 4 bytes, e.g., nk=4 for 128-bit key)

    // Output
    signal output blinded[k*bpl];       // 32 limbs * 8 bytes per limb = 256-byte blinded output
    signal output cipher[messageLen];   // encrypted message

    // 0) Hash the message
    component hasher = Sha256Bytes(messageLen);
    for (var i = 0; i < messageLen; i++) {
        hasher.in[i] <== message[i];
    }
    

    for (var i = 0; i < 32; i++) {
        log("hasher.out[", i, "] = ", hasher.out[i]);
    //     signed_attrs[digest_offset + i] === hasher.out[i]; 
    }

    // 1) Hash the signed_attrs
    component hasher2 = Sha256Bytes(signedAttrLen);
    for (var i = 0; i < signedAttrLen; i++) {
        hasher2.in[i] <== signed_attrs[i];
    }

    // // 2) Blind using RSA-PSS
    component blinder = BlindRSAPSS(w, k, eBits, 32, 32, mgfCount);
    // feed hashed output
    for (var i = 0; i < 32; i++) {
        blinder.hashed[i] <== hasher2.out[i];
    }
    // feed salt
    for (var i = 0; i < 32; i++) {
        blinder.salt[i] <== salt[i];
    }
    // feed blinding factor r, exponent, modulus
    for (var i = 0; i < 32; i++) {
        blinder.r[i] <== r[i];
        blinder.exp[i] <== exp[i];
        blinder.modulus[i] <== modulus[i];
    }

    // capture output
    for (var i = 0; i < 32 * 8; i++) {
        blinded[i] <== blinder.blinded[i];
    }

    // 3) Encrypt the blinded output using AES CTR
    
    component aes = EncryptCTR(messageLen, nk);
    for (var i = 0; i < messageLen; i++) {
        aes.plainText[i] <== message[i];
    }
    for (var i = 0; i < 16; i++) {
        aes.iv[i] <== iv[i];
    }
    for (var i = 0; i < nk*4; i++) {
        aes.key[i] <== key[i];
    }
    for (var i = 0; i < messageLen; i++) {
        cipher[i] <== aes.cipher[i];
    }


}

// component main { public [exp, modulus] } = TLSBlind(64, 32, 17, 7, 14711, 4);
component main { public [exp, modulus] } = TLSBlind(64, 32, 17, 7, {{SIGNED_ATTRS_LEN}}, {{MESSAGE_LEN}}, 4);
// component main { public [exp, modulus] } = TLSBlind(64, 32, 17, 7, 1536, 4);