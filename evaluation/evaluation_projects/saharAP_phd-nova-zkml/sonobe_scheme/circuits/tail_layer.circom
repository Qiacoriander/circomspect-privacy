pragma circom 2.0.0;
include "./node_modules/circomlib-ml/circuits/circomlib/mimc.circom";
include "./node_modules/circomlib-ml/circuits/Dense.circom";
include "./node_modules/circomlib-ml/circuits/ArgMax.circom";
include "./utils/mimcsponge.circom";
include "./utils/utils.circom";

template TailLayer(nInputs, nOutputs,n) {
    // activation outputed by the recursive layer
    signal input a_prev[nInputs]; 

    signal input dense_weights[nInputs][nOutputs];
    signal input dense_bias[nOutputs];
    signal input dense_out[nOutputs];
    signal input dense_remainder[nOutputs];
    signal input argMax_out; // label output
    
// Circuit logic starts here
    component dense = Dense(nInputs,nOutputs,10**n);
    component argMax= ArgMax(nOutputs);
  

    dense.in <== a_prev;
    dense.weights <== dense_weights;
    dense.bias <== dense_bias;
    dense.out <== dense_out;
    dense.remainder <== dense_remainder;

    // apply argmax to the output of the last layer
    argMax.in <== dense.out;
    argMax.out<== argMax_out;
}

component main { public [a_prev] }= TailLayer(10,10,18);
