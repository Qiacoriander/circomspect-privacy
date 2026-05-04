pragma circom 2.0.0;

template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc = 0;

    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0; 
        lc += out[i] * (1 << i);
    }
    lc === in; 
}

template LessThan(n) {
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n+1);
    n2b.in <== (1 << n) + in[0] - in[1];
    out <== 1 - n2b.out[n];
}

template Modulo(n) {
    signal input total;
    signal input p;
    signal output c;

    signal q;
    q <-- total \ p; 

    c <== total - q * p;

    total === q * p + c; 
    
    component lt = LessThan(n);
    lt.in[0] <== c;
    lt.in[1] <== p;
    lt.out === 1;
}

template Square() {
    signal input in;
    signal output out;
    out <== in * in;
}

template Main() {
    signal input a;
    signal input b;
    signal input p; 
    signal output c; 

    component a_sq = Square();
    a_sq.in <== a;

    component b_sq = Square();
    b_sq.in <== b;

    signal total;
    total <== a_sq.out + b_sq.out;

    component mod = Modulo(256);
    mod.total <== total;
    mod.p <== p;
    c <== mod.c;
}

component main {public [p]} = Main();