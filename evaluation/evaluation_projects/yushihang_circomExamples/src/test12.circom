pragma circom 2.1.0;

template to_binary(n) {
    signal input in[n];
    signal output {binary} out[n];
    out <== in;
}
template Bits2Num(n) {
    signal input {binary} in[n];
    signal output out;
    var lc1=0;

    var e2 = 1;
    for (var i = 0; i<n; i++) {
        lc1 += in[i] * e2;
        e2 = e2 + e2;
    }

    lc1 ==> out;
}

template A(){
    signal input  in[2];
    signal output out;

    out <== Bits2Num(2)(to_binary(2)(in));

   
}

component main  = A();