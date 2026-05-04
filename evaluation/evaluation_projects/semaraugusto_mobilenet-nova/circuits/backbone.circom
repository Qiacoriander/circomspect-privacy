pragma circom 2.1.1;

include "./utils/utils.circom";
include "./SeparableBNConv.circom";

template Backbone(nRows, nCols, nChannels, nDepthFilters, nPointFilters, n) {
    var kernelSize = 3;
    var strides = 1;

    // // [running of hash outputted by the previous layer, hash of the activations of the previous layer]
    signal input step_in[2];
    signal output step_out[2];

    signal input in[nRows][nCols][nChannels];

    signal input dw_conv_weights[kernelSize][kernelSize][nDepthFilters]; // H x W x C x K
    signal input dw_conv_bias[nDepthFilters];
    signal input dw_conv_out[nRows][nCols][nDepthFilters];
    signal input dw_conv_remainder[nRows][nCols][nDepthFilters];

    signal input dw_bn_a[nDepthFilters];
    signal input dw_bn_b[nDepthFilters];
    signal input dw_bn_out[nRows][nCols][nDepthFilters];
    signal input dw_bn_remainder[nRows][nCols][nDepthFilters];

    signal input pw_conv_weights[nDepthFilters][nPointFilters]; // weights are 2d because kernel_size is 1
    signal input pw_conv_bias[nPointFilters];
    signal input pw_conv_out[nRows][nCols][nPointFilters];
    signal input pw_conv_remainder[nRows][nCols][nPointFilters];

    signal input pw_bn_a[nPointFilters];
    signal input pw_bn_b[nPointFilters];
    signal input pw_bn_out[nRows][nCols][nPointFilters];
    signal input pw_bn_remainder[nRows][nCols][nPointFilters];

    // Hash input and check it matches step_in[1]
    log("BACKBONE STARTED");
    component mimc_input = MimcHashMatrix3D(nRows, nRows, nChannels);
    mimc_input.matrix <== in;
    log("STEP_IN     RESULT", step_in[1]);
    log("HASH OUTPUT RESULT", mimc_input.hash);
    step_in[1] === mimc_input.hash;

    // Hash depthwise weights
    component mimc_dw_weights = MimcHashMatrix3D(kernelSize, kernelSize, nChannels);
    mimc_dw_weights.matrix <== dw_conv_weights;
    log("WEIGHTS HASH RESULT", mimc_dw_weights.hash);

    // Hash biases and bn parameters
    component mimc_params = MimcHashScalarParams(nDepthFilters, nPointFilters);
    mimc_params.dw_conv_bias <== dw_conv_bias;
    mimc_params.dw_bn_a <== dw_bn_a;
    mimc_params.dw_bn_b <== dw_bn_b;

    mimc_params.pw_conv_bias <== pw_conv_bias;
    mimc_params.pw_bn_a <== pw_bn_a;
    mimc_params.pw_bn_b <== pw_bn_b;

    component mimc_pw_weights = MiMCSponge(nDepthFilters * nPointFilters, 91, 1);
    mimc_pw_weights.k <== 0;
    var i = 0;
    for (var row = 0; row < nDepthFilters; row++) {
        for (var col = 0; col < nPointFilters; col++) {
        mimc_pw_weights.ins[i] <== pw_conv_weights[row][col];
        i += 1;
        }
    }

    component mimc_composite = MiMCSponge(4, 91, 1);
    mimc_composite.k <== 0;
    mimc_composite.ins[0] <== step_in[0];
    mimc_composite.ins[1] <== mimc_dw_weights.hash;
    mimc_composite.ins[2] <== mimc_params.hash;
    mimc_composite.ins[3] <== mimc_pw_weights.outs[0];

    step_out[0] <== mimc_composite.outs[0];

    component mimc_hash_output = MimcHashMatrix3D(nRows, nCols, nPointFilters);
    mimc_hash_output.matrix <== pw_bn_out;
    step_out[1] <== mimc_hash_output.hash;


    component layer = SeparableBNConvolution(nRows, nCols, nChannels, nDepthFilters, nPointFilters, 10**15);
    layer.in <== in;
    layer.dw_conv_weights <== dw_conv_weights;
    layer.dw_conv_bias <== dw_conv_bias;
    layer.dw_conv_out <== dw_conv_out;
    layer.dw_conv_remainder <== dw_conv_remainder;

    layer.dw_bn_a <== dw_bn_a;
    layer.dw_bn_b <== dw_bn_b;
    layer.dw_bn_out <== dw_bn_out;
    layer.dw_bn_remainder <== dw_bn_remainder;

    layer.pw_conv_weights <== pw_conv_weights;
    layer.pw_conv_bias <== pw_conv_bias;
    layer.pw_conv_out <== pw_conv_out;
    layer.pw_conv_remainder <== pw_conv_remainder;

    layer.pw_bn_a <== pw_bn_a;
    layer.pw_bn_b <== pw_bn_b;
    layer.pw_bn_out <== pw_bn_out;
    layer.pw_bn_remainder <== pw_bn_remainder;

    log("LAYER DONE");

    log("step_in[0]", step_in[0]);
    log("step_in[1]", step_in[1]);
    // step_out[0] <== step_in[0] + 1;
    // step_out[1] <== step_in[0] + step_in[1];
    log("step_out[0]", step_out[0]);
    log("step_out[1]", step_out[1]);
    log("END");

    // component mimc_output = MimcHashMatrix3D(nRows, nRows, nPointFilters);
    // mimc_hash_activations.matrix <== pw_bn_out;
    // step_out[1] <== mimc_hash_activations.hash;
}

// component main = Backbone(7, 7, 3, 3, 6, 10**15);
component main { public [step_in] } = Backbone(32, 32, 32, 32, 32, 10**15);
