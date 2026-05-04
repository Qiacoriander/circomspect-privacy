pragma circom 2.0.0;
include "./node_modules/circomlib-ml/circuits/ReLU.circom";
include "./node_modules/circomlib-ml/circuits/circomlib/mimc.circom";
include "./node_modules/circomlib-ml/circuits/Dense.circom";
include "./node_modules/circomlib-ml/circuits/ArgMax.circom";
include "./utils/mimcsponge.circom";
include "./utils/utils.circom";

template HeadLayer(nInputs, nOutputs,n) {
    signal input in[nInputs];

    signal input dense_weights[nInputs][nOutputs];
    signal input dense_bias[nOutputs];
    signal input dense_out[nOutputs];
    signal input dense_remainder[nOutputs];
    
    signal input relu_out[nOutputs];

    component dense = Dense(nInputs,nOutputs,10**n);
    component relu[nOutputs];
    
    dense.in <== in;
    dense.weights <== dense_weights;
    dense.bias <== dense_bias;
    dense.out <== dense_out;
    dense.remainder <== dense_remainder;

    // apply ReLU to the output of the dense layer
    for (var i=0; i<nOutputs; i++) {
        relu[i] = ReLU();
        relu[i].in <== dense.out[i];
        relu[i].out <== relu_out[i];
    }
    
}
component main = HeadLayer(28*28,10,18);