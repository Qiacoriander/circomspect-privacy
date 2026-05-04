pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

//bigEndian
template Num2BitsBigEndian(l){
    signal input in;
    signal output out[l];

    component num2Bits = Num2Bits(l); 
    num2Bits.in <== in;
    for (var i=0; i< l; i++){
        out[i] <== num2Bits.out[l-i-1]; 
    }
}

template MultModP(n){
    assert(n <= 252);
    signal input a;
    signal input b;
    signal input p;

    signal output out;

    signal m;
    signal quotient;

    m <== a * b;
    quotient <-- m \ p;
    out <-- m % p;
    component lt = LessThan(n);
    lt.in[0] <== out;
    lt.in[1] <== p;
    lt.out === 1;
    m === quotient * p + out;
}



// modulus is a n-bit integer s.t. n <= 126
// exp is a l-bit integer s.t. l <= 253
// base < modulus
// out = base ^ exp % modulus
template powMod(n, l){
    assert(n <= 126);
    assert(l <= 254);
    signal input base;
    signal input exp;
    signal input modulus;
    signal output out;

    component exp2Bits = Num2BitsBigEndian(l);
    exp2Bits.in <== exp;// implicitly check that exp is l-bit

    
    component sqauring[l-1];
    component multiplying[l-1];
    
    signal outStep[l];
    
    outStep[0] <==  1 +  exp2Bits.out[0] * (base - 1);

    for(var i=0; i<l-1; i++){
        sqauring[i] = MultModP(n);
        sqauring[i].a <== outStep[i];
        sqauring[i].b <== outStep[i];
        sqauring[i].p <== modulus;

        multiplying[i] = MultModP(n);
        multiplying[i].a <== sqauring[i].out;
        multiplying[i].b <== base;
        multiplying[i].p <== modulus;
        
        outStep[i+1] <== sqauring[i].out + exp2Bits.out[i+1] * (multiplying[i].out - sqauring[i].out);
    }

    out <== outStep[l-1];
    
}






// component main {public [base, modulus]} = powMod(126, 126);