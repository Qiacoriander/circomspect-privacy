pragma circom 2.0.0;

template MultiMux1(n) {
    signal input c[n][2];  // Constants
    signal input s;   // Selector
    signal output out[n];

    for (var i=0; i<n; i++) {

        out[i] <== (c[i][1] - c[i][0])*s + c[i][0];

    }
}

template Mux1() {
    var i;
    signal input c[2];  // Constants
    signal input s;   // Selector
    signal output out;

    component mux = MultiMux1(1);

    for (i=0; i<2; i++) {
        mux.c[0][i] <== c[i];
    }

    s ==> mux.s;

    mux.out[0] ==> out;
}

template T() {

    component mux = Mux1();
    mux.c[0] <== 1;
    mux.c[1] <== 0;
    mux.s <== 0;

    log("mux.c[0] = ", mux.c[0]);
    log("mux.c[1] = ", mux.c[1]);
    log("mux.s    = ", mux.s);
    log("mux.out  = ", mux.out);

    log("(~ mux.out) = ", (~ mux.out));
    log("(~ 1)       = ", (~ 1));

}

component main = T();

/********

no bug

*********/