include "../../../node_modules/circomlib/circuits/bitify.circom";

template FieldArray8Number() {
    signal input f[8];
    signal output out;

    component f32[8];

    component bits2Num = Bits2Num(256);

    for(var i=0; i < 8; i++) {
        f32[i] = Num2Bits(32);
        f32[i].in <== f[i];

        for(var j = 0; j < 32; j++) {
            bits2Num.in[32*i + j] <== f32[i].out[31 - j];
        }
    }

    out <== bits2Num.out;
}