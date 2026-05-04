pragma circom 2.0.0;

template Check(){
    signal input a;
    signal input b;
    signal input p;
    signal output c;
    signal a2;
    signal b2;
    signal suma;
    signal resto;

    a2 <== a * a;
    b2 <== b * b;
    suma <== a2 + b2;

    resto <-- suma % p;

    c <== resto;

    signal one;
    one <-- 1;
    p * one === p;
}

component main {public [p]} = Check();