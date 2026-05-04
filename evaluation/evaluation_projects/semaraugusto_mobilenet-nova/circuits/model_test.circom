pragma circom 2.1.1;

include "./utils/utils.circom";
include "./SeparableBNConv.circom";

template Backbone2(nRows, nCols, nChannels, nDepthFilters, nPointFilters, n) {
    var kernelSize = 3;
    var strides = 1;

    // // [running of hash outputted by the previous layer, hash of the activations of the previous layer]
    signal input step_in[2];
    signal output step_out[2];

    signal input in[nRows][nCols][nChannels];

    signal input l0_dw_conv_weights[kernelSize][kernelSize][nDepthFilters]; // H x W x C x K
    signal input l0_dw_conv_bias[nDepthFilters];
    signal input l0_dw_conv_out[nRows][nCols][nDepthFilters];
    signal input l0_dw_conv_remainder[nRows][nCols][nDepthFilters];

    signal input l0_dw_bn_a[nDepthFilters];
    signal input l0_dw_bn_b[nDepthFilters];
    signal input l0_dw_bn_out[nRows][nCols][nDepthFilters];
    signal input l0_dw_bn_remainder[nRows][nCols][nDepthFilters];

    signal input l0_pw_conv_weights[nDepthFilters][nPointFilters]; // weights are 2d because kernel_size is 1
    signal input l0_pw_conv_bias[nPointFilters];
    signal input l0_pw_conv_out[nRows][nCols][nPointFilters];
    signal input l0_pw_conv_remainder[nRows][nCols][nPointFilters];

    signal input l0_pw_bn_a[nPointFilters];
    signal input l0_pw_bn_b[nPointFilters];
    signal input l0_pw_bn_out[nRows][nCols][nPointFilters];
    signal input l0_pw_bn_remainder[nRows][nCols][nPointFilters];


    signal input l1_dw_conv_weights[kernelSize][kernelSize][nDepthFilters]; // H x W x C x K
    signal input l1_dw_conv_bias[nDepthFilters];
    signal input l1_dw_conv_out[nRows][nCols][nDepthFilters];
    signal input l1_dw_conv_remainder[nRows][nCols][nDepthFilters];

    signal input l1_dw_bn_a[nDepthFilters];
    signal input l1_dw_bn_b[nDepthFilters];
    signal input l1_dw_bn_out[nRows][nCols][nDepthFilters];
    signal input l1_dw_bn_remainder[nRows][nCols][nDepthFilters];

    signal input l1_pw_conv_weights[nDepthFilters][nPointFilters]; // weights are 2d because kernel_size is 1
    signal input l1_pw_conv_bias[nPointFilters];
    signal input l1_pw_conv_out[nRows][nCols][nPointFilters];
    signal input l1_pw_conv_remainder[nRows][nCols][nPointFilters];

    signal input l1_pw_bn_a[nPointFilters];
    signal input l1_pw_bn_b[nPointFilters];
    signal input l1_pw_bn_out[nRows][nCols][nPointFilters];
    signal input l1_pw_bn_remainder[nRows][nCols][nPointFilters];

    log("MODEL TEST STARTED");
    component l0_mimc_input = MimcHashMatrix3D(nRows, nRows, nChannels);
    l0_mimc_input.matrix <== in;
    log("STEP_IN     RESULT", step_in[1]);
    log("HASH OUTPUT RESULT", l0_mimc_input.hash);
    step_in[1] === l0_mimc_input.hash;

    // Hash depthwise weights
    component l0_mimc_dw_weights = MimcHashMatrix3D(kernelSize, kernelSize, nChannels);
    l0_mimc_dw_weights.matrix <== l0_dw_conv_weights;
    log("WEIGHTS HASH RESULT", l0_mimc_dw_weights.hash);

    // Hash biases and bn parameters
    component l0_mimc_params = MimcHashScalarParams(nDepthFilters, nPointFilters);
    l0_mimc_params.dw_conv_bias <== l0_dw_conv_bias;
    l0_mimc_params.dw_bn_a <== l0_dw_bn_a;
    l0_mimc_params.dw_bn_b <== l0_dw_bn_b;

    l0_mimc_params.pw_conv_bias <== l0_pw_conv_bias;
    l0_mimc_params.pw_bn_a <== l0_pw_bn_a;
    l0_mimc_params.pw_bn_b <== l0_pw_bn_b;
    log("PARAMS HASH RESULT", l0_mimc_params.hash);

    component l0_mimc_pw_weights = MiMCSponge(nDepthFilters * nPointFilters, 91, 1);
    l0_mimc_pw_weights.k <== 0;
    var i = 0;
    for (var row = 0; row < nDepthFilters; row++) {
        for (var col = 0; col < nPointFilters; col++) {
        l0_mimc_pw_weights.ins[i] <== l0_pw_conv_weights[row][col];
        // signal input pw_conv_weights[nDepthFilters][nPointFilters]; // weights are 2d because kernel_size is 1
        i += 1;
        }
    }
    log("POINTWISE WEIGHTS HASH RESULT", l0_mimc_pw_weights.outs[0]);

    component l0_mimc_hash_output = MimcHashMatrix3D(nRows, nCols, nPointFilters);
    l0_mimc_hash_output.matrix <== l0_pw_bn_out;
    log("OUTPUT HASH RESULT", l0_mimc_hash_output.hash);

    component l0_mimc_composite = MiMCSponge(4, 91, 1);
    l0_mimc_composite.k <== 0;
    l0_mimc_composite.ins[0] <== step_in[0];
    l0_mimc_composite.ins[1] <== l0_mimc_dw_weights.hash;
    l0_mimc_composite.ins[2] <== l0_mimc_params.hash;
    l0_mimc_composite.ins[3] <== l0_mimc_pw_weights.outs[0];

    signal output l0_step_out[2];
    l0_step_out[0] <== l0_mimc_composite.outs[0];
    l0_step_out[1] <== l0_mimc_hash_output.hash;
    log("L0_STEP_OUT[0] RESULT", l0_step_out[0]);
    log("L0_STEP_OUT[1] RESULT", l0_step_out[1]);




    component layer = SeparableBNConvolution(nRows, nCols, nChannels, nDepthFilters, nPointFilters, 10**15);
    layer.in <== in;
    layer.dw_conv_weights <== l0_dw_conv_weights;
    layer.dw_conv_bias <== l0_dw_conv_bias;
    layer.dw_conv_out <== l0_dw_conv_out;
    layer.dw_conv_remainder <== l0_dw_conv_remainder;

    layer.dw_bn_a <== l0_dw_bn_a;
    layer.dw_bn_b <== l0_dw_bn_b;
    layer.dw_bn_out <== l0_dw_bn_out;
    layer.dw_bn_remainder <== l0_dw_bn_remainder;

    layer.pw_conv_weights <== l0_pw_conv_weights;
    layer.pw_conv_bias <== l0_pw_conv_bias;
    layer.pw_conv_out <== l0_pw_conv_out;
    layer.pw_conv_remainder <== l0_pw_conv_remainder;

    layer.pw_bn_a <== l0_pw_bn_a;
    layer.pw_bn_b <== l0_pw_bn_b;
    layer.pw_bn_out <== l0_pw_bn_out;
    layer.pw_bn_remainder <== l0_pw_bn_remainder;
    log("LAYER 0 DONE");



    component l1_mimc_dw_weights = MimcHashMatrix3D(kernelSize, kernelSize, nChannels);
    l1_mimc_dw_weights.matrix <== l1_dw_conv_weights;
    log("WEIGHTS HASH RESULT", l1_mimc_dw_weights.hash);

    // Hash biases and bn parameters
    component l1_mimc_params = MimcHashScalarParams(nDepthFilters, nPointFilters);
    l1_mimc_params.dw_conv_bias <== l1_dw_conv_bias;
    l1_mimc_params.dw_bn_a <== l1_dw_bn_a;
    l1_mimc_params.dw_bn_b <== l1_dw_bn_b;

    l1_mimc_params.pw_conv_bias <== l1_pw_conv_bias;
    l1_mimc_params.pw_bn_a <== l1_pw_bn_a;
    l1_mimc_params.pw_bn_b <== l1_pw_bn_b;
    log("PARAMS HASH RESULT", l1_mimc_params.hash);

    component l1_mimc_pw_weights = MiMCSponge(nDepthFilters * nPointFilters, 91, 1);
    l1_mimc_pw_weights.k <== 0;
    i = 0;
    for (var row = 0; row < nDepthFilters; row++) {
        for (var col = 0; col < nPointFilters; col++) {
        l1_mimc_pw_weights.ins[i] <== l1_pw_conv_weights[row][col];
        // signal input pw_conv_weights[nDepthFilters][nPointFilters]; // weights are 2d because kernel_size is 1
        i += 1;
        }
    }
    log("POINTWISE WEIGHTS HASH RESULT", l1_mimc_pw_weights.outs[0]);

    component l1_mimc_hash_output = MimcHashMatrix3D(nRows, nCols, nPointFilters);
    l1_mimc_hash_output.matrix <== l1_pw_bn_out;
    log("OUTPUT HASH RESULT", l1_mimc_hash_output.hash);

    component l1_mimc_composite = MiMCSponge(4, 91, 1);
    l1_mimc_composite.k <== 0;
    l1_mimc_composite.ins[0] <== l0_step_out[0];
    l1_mimc_composite.ins[1] <== l1_mimc_dw_weights.hash;
    l1_mimc_composite.ins[2] <== l1_mimc_params.hash;
    l1_mimc_composite.ins[3] <== l1_mimc_pw_weights.outs[0];

    // signal output l1_step_out[2];
    step_out[0] <== l1_mimc_composite.outs[0];
    step_out[1] <== l1_mimc_hash_output.hash;
    log("STEP_OUT[0] RESULT", step_out[0]);
    log("STEP_OUT[1] RESULT", step_out[1]);



    component layer1 = SeparableBNConvolution(nRows, nCols, nChannels, nDepthFilters, nPointFilters, 10**15);
    layer1.in <== l0_pw_bn_out;
    layer1.dw_conv_weights <== l1_dw_conv_weights;
    layer1.dw_conv_bias <== l1_dw_conv_bias;
    layer1.dw_conv_out <== l1_dw_conv_out;
    layer1.dw_conv_remainder <== l1_dw_conv_remainder;

    layer1.dw_bn_a <== l1_dw_bn_a;
    layer1.dw_bn_b <== l1_dw_bn_b;
    layer1.dw_bn_out <== l1_dw_bn_out;
    layer1.dw_bn_remainder <== l1_dw_bn_remainder;

    layer1.pw_conv_weights <== l1_pw_conv_weights;
    layer1.pw_conv_bias <== l1_pw_conv_bias;
    layer1.pw_conv_out <== l1_pw_conv_out;
    layer1.pw_conv_remainder <== l1_pw_conv_remainder;

    layer1.pw_bn_a <== l1_pw_bn_a;
    layer1.pw_bn_b <== l1_pw_bn_b;
    layer1.pw_bn_out <== l1_pw_bn_out;
    layer1.pw_bn_remainder <== l1_pw_bn_remainder;
    log("LAYER 1 DONE");

}

// component main = Backbone(7, 7, 3, 3, 6, 10**15);
// component main = Backbone(32, 32, 96, 96, 96, 10**15);
component main { public [step_in] } = Backbone2(32, 32, 32, 32, 32, 10**15);
