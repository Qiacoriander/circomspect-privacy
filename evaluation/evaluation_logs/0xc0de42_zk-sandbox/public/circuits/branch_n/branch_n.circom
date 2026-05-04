pragma circom 2.1.8;

include "comparators.circom";
include "multiplexer.circom";


template BranchN(n) {
    assert (n > 1);
    signal input x;
    signal input conditions[n-1];
    signal input branches[n];
    signal output out;

    signal switches[n];

    component isEqual[n];
    for(var i = 0; i < n-1; i++) {
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== x;
        isEqual[i].in[1] <== conditions[i];
        switches[i] <== isEqual[i].out;
    }

    var otherwise_acc = 0;
    for( var i = 0; i < n-1; i++) {
        otherwise_acc += switches[i];
    }

    switches[n-1] <== IsZero()(otherwise_acc); 

    component InnerProduct = EscalarProduct(n);

    for (var i = 0; i < n; i++) {
        InnerProduct.in1[i] <== branches[i];
        InnerProduct.in2[i] <== switches[i];
    }
    out <== InnerProduct.out;
}

template MultiBranchConditional() {
    signal input x;

    signal output out;

    component branchn = BranchN(4);

    var conditions[3] = [5, 9, 10];
    var branches[4] = [14, 22, 23, 45];
    for (var i = 0; i < 4; i++) {
    if (i < 3) {
        branchn.conditions[i] <== conditions[i];
    }

    branchn.branches[i] <== branches[i];
    }

    branchn.x <== x;
    branchn.out ==> out;
}

component main = MultiBranchConditional();