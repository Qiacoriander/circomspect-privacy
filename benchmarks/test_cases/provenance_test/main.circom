pragma circom 2.0.0;

template Main() {
    signal input a; // private
    signal input b; // private
    signal input c; // private
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;

    // Direct taint: out1 depends only on a
    out1 <== a;

    // Mixed taint: out2 depends on b and c
    out2 <== b * c;

    // Mixed taint via addition: out3 depends on a and c
    out3 <== a + c;

    // Duplicate taint: out4 depends on a (same as out1)
    out4 <== a;
}

component main = Main();
