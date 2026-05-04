pragma circom 2.0.0;

template T() {
    var prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    signal a;
    signal b;
    a <-- prime | 1;
    b <-- prime & 1;
}

component main = T();

/********

bug in : 2.1.8
may fixed in : 2.2.0

*********/