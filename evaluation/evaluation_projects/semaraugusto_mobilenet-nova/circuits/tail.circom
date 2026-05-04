pragma circom 2.1.1;

include "./utils/utils.circom";
include "./AveragePooling2D.circom";
include "./Dense.circom";

template Tail(n) {
    // H x W x C
    var inputSize = 32;
    var paddedInputSize = 34;
    var nChannels = 32;
    var nOutputs = 10;
    var nConvFilters = 3;
    var kernelSize = 3;

    var avgPoolSize = 6;
    var padding = 13;
    signal input step_in[2];
    signal input in[inputSize][inputSize][nChannels];
    signal input avg_pool_out[1][1][nChannels];
    signal input avg_pool_remainder[1][1][nChannels];

    signal input dense_weights[nChannels][nOutputs];
    signal input dense_bias[nOutputs];
    signal input dense_out[nOutputs];
    signal input dense_remainder[nOutputs];

    signal output step_out[2];

    log("TAIL STARTED");

    // Check if input has been hashed correctly and is on step_in[1]

    // Compute Average pooling over the padded cube.
    component pooling = AveragePooling2D (avgPoolSize, avgPoolSize, nChannels, avgPoolSize, 1);
    for (var i=padding; i<inputSize-padding; i++) {
        for (var j=padding; j<inputSize-padding; j++) {
            for (var k=0; k<nChannels; k++) {
                pooling.in[i-padding][j-padding][k] <== in[i][j][k];
            }
        }
    }
    for (var k=0; k<nChannels; k++) {
        pooling.out[0][0][k] <== avg_pool_out[0][0][k];
        pooling.remainder[0][0][k] <== avg_pool_remainder[0][0][k];
    }
    log("end pooling");

    component mimc_input = MimcHashMatrix3D(inputSize, inputSize, nChannels);
    mimc_input.matrix <== in;
    // log("MIMC_INPUT HASH : ", mimc_input.hash);

    // Compute Linear layer the result of the average pool.
    component dense = Dense (nChannels, nOutputs, n);
    dense.in <== avg_pool_out[0][0];
    dense.weights <== dense_weights;
    dense.bias <== dense_bias;
    dense.out <== dense_out;
    dense.remainder <== dense_remainder;
    //
    log("end dense");
    signal output out;

    step_in[1] === mimc_input.hash;

    // Compute Hash
    component mimc_model = MiMCSponge(nChannels*nOutputs + nOutputs+1, 91, 1);
    mimc_model.k <== 0;
    mimc_model.ins[0] <== step_in[0];
    var i = 1;
    for (var row=0; row<nChannels; row++) {
        for (var col=0; col<nOutputs; col++) {
            mimc_model.ins[i] <== dense_weights[row][col];
            i += 1;
        }
    }
    for (var row=0; row<nOutputs; row++) {
        mimc_model.ins[i] <== dense_bias[row];
        i += 1;
    }
    step_out[0] <== mimc_model.outs[0];

    component mimc_output = MiMCSponge(nOutputs, 91, 1);
    mimc_output.k <== 0;
    for (var i=0; i<nOutputs; i++) {
        mimc_output.ins[i] <== dense_out[i];
    }
    step_out[1] <== mimc_output.outs[0];

    out <== 1; 
    log("end!!");
}

component main { public [ step_in, dense_out ] } = Tail(10**15);
// component main = Tail(10**15);

