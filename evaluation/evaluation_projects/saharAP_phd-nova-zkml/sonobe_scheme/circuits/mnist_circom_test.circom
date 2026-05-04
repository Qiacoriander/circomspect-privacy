pragma circom 2.0.0;
include "./node_modules/circomlib-ml/circuits/ReLU.circom";
include "./node_modules/circomlib-ml/circuits/circomlib/mimc.circom";
include "./node_modules/circomlib-ml/circuits/Dense.circom";
include "./node_modules/circomlib-ml/circuits/ArgMax.circom";
include "./utils/mimcsponge.circom";
include "./utils/utils.circom";

template mnist{
    signal input in[784];

    signal input relu_out[10];

    signal input dense_1_weights[784][10];
    signal input dense_1_bias[10];
    signal input dense_1_out[10];
    signal input dense_1_remainder[10];

    signal input dense_2_weights[10][10];
    signal input dense_2_bias[10];
    signal input dense_2_out[10];
    signal input dense_2_remainder[10];

    signal input argmax_out;

    signal output out;

    component dense_1 = Dense(784,10,10**18);
    component relu[10];
    component dense_2 = Dense(10,10,10**18);
    component argmax = ArgMax(10);

    for (var i = 0; i < 784; i++) {
        dense_1.in[i] <== in[i];
        for (var j=0; j<10; j++) {
            dense_1.weights[i][j] <== dense_1_weights[i][j];
        }
    }
       for (var i=0; i<10; i++) {
        dense_1.bias[i] <== dense_1_bias[i];
    }

    for (var i=0; i<10; i++) {
        dense_1.out[i] <== dense_1_out[i];
        dense_1.remainder[i] <== dense_1_remainder[i];
    }
    // apply ReLU to the output of the first dense layer
    for (var i=0; i<10; i++) {
        relu[i] = ReLU();
        relu[i].in <== dense_1.out[i];
        relu[i].out <== relu_out[i];
    }

    for (var i = 0; i < 10; i++) {
        dense_2.in[i] <==  relu[i].out;
        for (var j=0; j<10; j++) {
            dense_2.weights[i][j] <== dense_2_weights[i][j];
        }
    }
       for (var i=0; i<10; i++) {
        dense_2.bias[i] <== dense_2_bias[i];
    }

    for (var i=0; i<10; i++) {
        dense_2.out[i] <== dense_2_out[i];
        dense_2.remainder[i] <== dense_2_remainder[i];
        argmax.in[i] <== dense_2.out[i];
    }
    argmax.out <== argmax_out;
    out <== argmax.out;
}
component main = mnist();