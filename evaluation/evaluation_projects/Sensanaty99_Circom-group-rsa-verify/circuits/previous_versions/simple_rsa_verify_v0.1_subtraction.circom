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
    signal output out[32];

    // sign ** exp mod modulus
    component pm = PowerMod(w, nb, e_bits);
    for (var i  = 0; i < nb; i++) {
        pm.base[i] <== sign[i];
        pm.exp[i] <== exp[i];
        pm.modulus[i] <== modulus[i];
    }

    //First method: we check the check if pm.out[i] is lesser than expected, map the subtractions of the values and multiply them to their corresponding signals, takes around 25s for the first 4 octet strings using Macbook Air M1 2020 w/ 16GB Ram.

    //signal used to verify that the signature verification is successful for every octet string.
        //signal interm[32];

    //component array to determine at each iteration if the octet string is less or equal to the expected value.
    //This is because, at the end of the verification, the difference between the signature decryption and the expected decryption must be 0.
    //in order to do this, the difference between pm.out[i] and expected[i], for each octet string i, must be 0. Therefore, adding every difference for every octet string should add up to 0.
    //Since one side can be larger than the other at any given time, we cannot rely on addition only because of negative differences, since -1 + 1 = 0, just the same as 0+0=0. If we always guarantee that differences are >=0, then surely the addition of all differences will always be >=0
    component lessThan[32];
    //this subtractions array stores, for every i in pm.out, two elements: 
    //subtractions[i*2] = pm.out[i] - something
    //subtractions[i*2+1] =  something - pm.out[i]
    //This is needed to build the constraint used by multiplications
    signal subtractions[64];
    //this less array stores 1 or 0 if for any octet string i, its value is lesser than the expected, or not, respectively.
    signal less[32];
    //this multiplications array stores, for every i in pm.out, two elements: 
    //multiplications[i*2] = less[i] * subtractions[i*2]
    //multiplications[i*2+1] =  less[i] * subtractions[i*2+1]
    //This is needed to build the constraint used by interm
    signal multiplications[64];

    // 1. Check hashed data
    // 64 * 4 = 256 bit. the first 4 numbers
    
    
    //First method:
    
    for (var i = 0; i < hashLen; i++) {
        lessThan[i] = LessThan(64);
        lessThan[i].in[0] <== pm.out[i];
        lessThan[i].in[1] <== hashed[i];
        less[i] <== lessThan[i].out;
        
        subtractions[i*2] <== pm.out[i] - hashed[i];
        //var biggerSubstraction = subtractions[i*2];
        multiplications[i*2] <== less[i] * subtractions[i*2];
        //var bigger = less[i] * biggerSubstraction;
        var bigger = multiplications[i*2];

        subtractions[i*2+1] <== hashed[i] - pm.out[i];
        //var lesserSubtraction = subtractions[i*2+1];
        multiplications[i*2+1] <== less[i] * subtractions[i*2+1];
        //var lesser = less[i] * lesserSubtraction;
        var lesser = multiplications[i*2+1];
        
        interm[i] <== bigger + lesser;        
    }
    

/*
    // 2. Check hash prefix and 1 byte 0x00
    // sha256/152 bit
    // 0b00110000001100010011000000001101000001100000100101100000100001100100100000000001011001010000001100000100000000100000000100000101000000000000010000100000
    // and remain 24 bit
    // 3. Check PS and em[1] = 1. the same code like golang std lib rsa.VerifyPKCS1v15
    var hashprefix[3] = [217300885422736416, 938447882527703397, 18446744069417742640];
    //var hashprefixIdx = 0;
    for (var i = 4; i<7; i++) {
        lessThan[i] = LessThan(64);
        lessThan[i].in[0] <== pm.out[i];
        lessThan[i].in[1] <== hashprefix[i-4];
        less[i] <== lessThan[i].out;

        subtractions[i*2] <== pm.out[i] - hashprefix[i-4];
        var biggerSubstraction = subtractions[i*2];
        var bigger = less[i] * biggerSubstraction;

        subtractions[i*2+1] <== hashprefix[i-4] - pm.out[i];
        var lesserSubtraction = subtractions[i*2+1];
        var lesser = less[i] * lesserSubtraction;

        interm[i] <== bigger + lesser;        

    }

    var ff = 18446744073709551615;
    for (var i = 7; i < 31; i++) {
        // 0b1111111111111111111111111111111111111111111111111111111111111111
        lessThan[i] = LessThan(64);
        lessThan[i].in[0] <== pm.out[i];
        lessThan[i].in[1] <== ff;
        less[i] <== lessThan[i].out;

        subtractions[i*2] <== pm.out[i] - ff;
        var biggerSubstraction = subtractions[i*2];
        var bigger = less[i] * biggerSubstraction;

        subtractions[i*2+1] <== ff - pm.out[i*2+1];
        var lesserSubtraction = subtractions[i+1];
        var lesser = less[i] * lesserSubtraction;

        interm[i] <== bigger + lesser;  
    }

    // 0b1111111111111111111111111111111111111111111111111
    var paddingStart = 562949953421311;
    lessThan[31] = LessThan(64);
    lessThan[31].in[0] <== pm.out[31];
    lessThan[31].in[1] <== paddingStart;
    less[31] <== lessThan[31].out;

    subtractions[62] <== pm.out[31] - paddingStart;
    var biggerSubstraction = subtractions[62];
    var bigger = less[31] * biggerSubstraction;

    subtractions[63] <== ff - pm.out[31];
    var lesserSubtraction = subtractions[63];
    var lesser = less[31] * lesserSubtraction;

    interm[31] <== bigger + lesser;

    //-------------result-------------

    out[0] <== interm[0];

    //we can add all numbers because even though they are 64 bit, 32*(2**64) is only under 70 bits < 254 and therefore circom can handle it.
    for (var i=1; i<31; i++) {
        out[i] <== out[i-1]+interm[i];
    }

    out[31] <== out[30]+interm[31];

    //Comment this out before going for group signatures:
    out[31] === 0;

*/

}

