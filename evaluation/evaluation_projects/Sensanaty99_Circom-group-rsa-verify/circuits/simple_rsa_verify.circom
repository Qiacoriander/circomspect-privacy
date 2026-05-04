pragma circom 2.0.0;

include "./pow_mod.circom";
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
template simple_RsaVerifyPkcs1v15(w, nb, e_bits, hashLen) {
    signal input exp[nb];
    signal input sign[nb];
    signal input modulus[nb];
    signal input hashed[hashLen];
    signal output out;

    // sign ** exp mod modulus
    component pm = PowerMod(w, nb, e_bits);
    for (var i  = 0; i < nb; i++) {
        pm.base[i] <== sign[i];
        pm.exp[i] <== exp[i];
        pm.modulus[i] <== modulus[i];
    }

    //Second method: Using the isEqual function, we can skip multiple signals. This method takes around 24.7s for the entire signature using Macbook Air M1 2020 w/ 16GB Ram.
    //component used to check for every octet string i, if it is equal to the expected octet string
    component isEqual[32];
    //signal array to determine for each octet string i, if it is equal to the expected octet string
    signal equal[32];


    // 1. Check hashed data
    // 64 * 4 = 256 bit. the first 4 numbers
    for (var i = 0; i < hashLen; i++) {
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== pm.out[i];
        isEqual[i].in[1] <== hashed[i];
        equal[i] <== isEqual[i].out;            
    }

    // 2. Check hash prefix and 1 byte 0x00
    // sha256/152 bit
    // 0b00110000001100010011000000001101000001100000100101100000100001100100100000000001011001010000001100000100000000100000000100000101000000000000010000100000
    // and remain 24 bit
    // 3. Check PS and em[1] = 1. the same code like golang std lib rsa.VerifyPKCS1v15
    var hashprefix[3] = [217300885422736416, 938447882527703397, 18446744069417742640];
    //var hashprefixIdx = 0;
    for (var i = 4; i<7; i++) {
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== pm.out[i];
        isEqual[i].in[1] <== hashprefix[i-4];
        equal[i] <== isEqual[i].out;         
    }

    // 4. check PM for 24 octet strings
    var ff = 18446744073709551615;
    for (var i = 7; i < 31; i++) {
        // 0b1111111111111111111111111111111111111111111111111111111111111111
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== pm.out[i];
        isEqual[i].in[1] <== ff;
        equal[i] <== isEqual[i].out;  
    }


    // 5. check 0x00 0x01 FF FF
    // 0b1111111111111111111111111111111111111111111111111
    var paddingStart = 562949953421311;

    isEqual[31] = IsEqual();
    isEqual[31].in[0] <== pm.out[31];
    isEqual[31].in[1] <== paddingStart;
    equal[31] <== isEqual[31].out;  

    //-------------result-------------
    signal interm[32];

    interm[0] <== equal[0];

    //we can add all numbers because even though they are 64 bit, 32*(2**64) is only under 70 bits < 254 and therefore circom can handle it.
    for (var i=1; i<31; i++) {
        interm[i] <== interm[i-1]+equal[i];
    }

    interm[31] <== interm[30]+equal[31];

    //Comment this out before going for group signatures:
    component signatureVerifies = IsEqual();
    signatureVerifies.in[0] <== interm[31];
    signatureVerifies.in[1] <== 32;
    out <== signatureVerifies.out;



}

