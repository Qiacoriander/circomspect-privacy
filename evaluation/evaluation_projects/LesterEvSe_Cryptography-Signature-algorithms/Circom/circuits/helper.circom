pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../bigInt/bigInt.circom";

// sha256(msg) to u64 4
// Get sha256 bits in Big-Endian format
    /*
    component hashed = Sha256(MSG_BITS);
    component n2b[MSG_BYTES];

    signal output out[4];

    for (var i = 0; i < MSG_BYTES; i++) {
        n2b[i] = Num2Bits(8);
        n2b[i].in <== message[i];

        for (var j = 0; j < 8; j++) {
            hashed.in[i*8 + j] <== n2b[i].out[7 - j];
        }
    }

    component hash_msg[4];
    for (var i = 0; i < 4; i++) {
        hash_msg[i] = Bits2Num(64);

        for (var j = 0; j < 64; j++) {
            // Reverse order of bytes and dwords
            hash_msg[i].in[j] <== hashed.out[255 - 64*i - j];
        }

        out[i] <== hash_msg[i].out;
    }
    */

// w = 32 (number bits)
// e_bits = 17
// nb is the length of the base and modulus
// calculates (base^exp) % modulus, exp = 2^(e_bits - 1) + 1 = 2^16 + 1
template PowerMod(w, nb, e_bits) {
    assert(e_bits >= 2);

    signal input base[nb];
    signal input modulus[nb];
    signal output out[nb];

    component muls[e_bits];

    for (var i = 0; i < e_bits; i++) {
        muls[i] = BigMultModP(w, nb);

        for (var j = 0; j < nb; j++) {
            muls[i].p[j] <== modulus[j];
        }
    }

    for (var i = 0; i < nb; i++) {
        muls[0].a[i] <== base[i];
        muls[0].b[i] <== base[i];
    }

    for (var i = 1; i < e_bits - 1; i++) {
        for (var j = 0; j < nb; j++) {
            muls[i].a[j] <== muls[i - 1].out[j];
            muls[i].b[j] <== muls[i - 1].out[j];
        }
    }

    for (var i = 0; i < nb; i++) {
        muls[e_bits - 1].a[i] <== base[i];
        muls[e_bits - 1].b[i] <== muls[e_bits - 2].out[i];
    }

    for (var i = 0; i < nb; i++) {
        out[i] <== muls[e_bits - 1].out[i];
    }
}