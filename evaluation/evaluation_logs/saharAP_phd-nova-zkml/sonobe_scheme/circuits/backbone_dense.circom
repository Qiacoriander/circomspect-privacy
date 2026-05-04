pragma circom 2.0.0;
include "./node_modules/circomlib-ml/circuits/ReLU.circom";
include "./node_modules/circomlib-ml/circuits/Dense.circom";

template BackboneDense(nInputs, nOutputs,n) {
    // activation outputed by the previous layer
    signal input ivc_input[nInputs]; // IVC input

    signal input external_inputs[nInputs * nOutputs+ nOutputs+ nOutputs+ nOutputs+ nOutputs];

    signal output ivc_output[nOutputs]; // IVC output
// external inputs
    
    // signal input dense_1_weights[nInputs][nOutputs];
    // signal input dense_1_bias[nOutputs];
    // signal input dense_1_out[nOutputs];
    // signal input dense_1_remainder[nOutputs];
    // signal input relu_out[nOutputs];
    // convert external inputs to the circit inputs

    // decoding external inputs to the circuit inputs
    signal dense_weights[nInputs][nOutputs];
    signal dense_bias[nOutputs];
    signal dense_out[nOutputs];
    signal dense_remainder[nOutputs];
    signal relu_out[nOutputs];
    for (var i = 0; i < nInputs; i++) {
        for (var j=0; j<nOutputs; j++) {
            dense_weights[i][j] <-- external_inputs[i*nOutputs+j];
        }
    }
    
    for (var i=0; i<nOutputs; i++) {
        dense_bias[i] <-- external_inputs[nInputs*nOutputs+i];
    }
    
    for (var i=0; i<nOutputs; i++) {
        dense_out[i] <-- external_inputs[nInputs*nOutputs+nOutputs+i];
    }
    
    for (var i=0; i<nOutputs; i++) {
        dense_remainder[i] <-- external_inputs[nInputs*nOutputs+nOutputs+nOutputs+i];
    }
    
    for (var i=0; i<nOutputs; i++) {
        relu_out[i] <-- external_inputs[nInputs*nOutputs+nOutputs+nOutputs+nOutputs+i];
    }
    
// Circuit logic starts here
    component dense = Dense(nInputs,nOutputs,10**n);
    component relu[nOutputs];
  
    dense.in <== ivc_input;
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
    ivc_output<== relu_out;
}
