pragma circom 2.0.0;

include "./pow_mod_revisioned.circom";
//include "../circomlib/circuits/comparators.circom";

template NumToBits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

// Pkcs1v15 + Sha256
// exp 65537
template simple_RsaVerifyPkcs1v15_v2(w, nb, e_bits, hashLen) {
    signal input exp[nb];
    signal input sign[nb];
    signal input modulus[nb];
    signal input hashed[hashLen];
    //signal output out;

    // sign ** exp mod modulus
    component pm = PowerMod(w, nb, e_bits);
    pm.base <== sign;
    //pm.exp <== exp;
    pm.modulus <== modulus;


    // for (var i  = 0; i < nb; i++) {
    //     pm.base[i] <== sign[i];
    //     pm.exp[i] <== exp[i];
    //     pm.modulus[i] <== modulus[i];
    // }
 
    pm.out[0] === hashed[0];
    pm.out[1] === hashed[1];
    pm.out[2] === hashed[2];
    pm.out[3] === hashed[3];

    pm.out[4] === 217300885422736416;
    pm.out[5] === 938447882527703397;
    pm.out[6] === 18446744069417742640;
    pm.out[7] === 18446744073709551615;

    pm.out[8] === 18446744073709551615;
    pm.out[9] === 18446744073709551615;
    pm.out[10] === 18446744073709551615;
    pm.out[11] === 18446744073709551615;
    pm.out[12] === 18446744073709551615;
    pm.out[13] === 18446744073709551615;
    pm.out[14] === 18446744073709551615;
    pm.out[15] === 18446744073709551615;
    pm.out[16] === 18446744073709551615;
    pm.out[17] === 18446744073709551615;
    pm.out[18] === 18446744073709551615;
    pm.out[19] === 18446744073709551615;
    pm.out[20] === 18446744073709551615;
    pm.out[21] === 18446744073709551615;
    pm.out[22] === 18446744073709551615;
    pm.out[23] === 18446744073709551615;
    pm.out[24] === 18446744073709551615;
    pm.out[25] === 18446744073709551615;
    pm.out[26] === 18446744073709551615;
    pm.out[27] === 18446744073709551615;
    pm.out[28] === 18446744073709551615;
    pm.out[29] === 18446744073709551615;
    pm.out[30] === 18446744073709551615;

    pm.out[31] === 562949953421311;
     
}

