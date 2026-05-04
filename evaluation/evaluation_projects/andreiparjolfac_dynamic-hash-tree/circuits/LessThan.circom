pragma circom 2.1.6;

include "./Num2Bits.circom";

template LessThan(){
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(253);

    n2b.in <== in[0]+(1<<252)-in[1];
    out <== 1-n2b.out[252];
}
