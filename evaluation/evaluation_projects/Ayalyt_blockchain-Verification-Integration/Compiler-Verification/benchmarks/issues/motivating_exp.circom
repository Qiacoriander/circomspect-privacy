pragma circom 2.0.0;

template exp(){
    signal input a;
    signal output out1;
    signal output out2;
    
    var p =  21888242871839275222246405745257275088548364400416034343698204186575808495617;

    out1 <-- 3 ** p;
    out2 <-- 3 ** (p + 0);
}

component main = exp();

/********

bug in : 2.1.8
may fixed in : 2.2.2

*********/
