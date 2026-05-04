pragma circom 2.1.8;
include "comparators.circom";


template IsSortedArray(len) {
    assert (len > 0);
    signal input numbers[len];
    component lessThan[len-1];
    
    for(var i=0; i < len-1; i++) {
        lessThan[i] = LessEqThan(252);
        lessThan[i].in[0] <== numbers[i];
        lessThan[i].in[1] <== numbers[i+1];
        lessThan[i].out === 1;
    }
}

component main =  IsSortedArray(10);