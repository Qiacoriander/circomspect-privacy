pragma circom 2.1.1;
// include "./Conv2D.circom";

include "./node_modules/circomlib/circuits/sign.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./node_modules/circomlib/circuits/comparators.circom";
include "./node_modules/circomlib-matrix/circuits/matElemMul.circom";
include "./node_modules/circomlib-matrix/circuits/matElemSum.circom";
include "./paddedDepthwiseConv.circom";
include "./PointwiseConv2D.circom";
include "./PaddedBatchNormalization2D.circom";
// include "./node_modules/circomlib-ml/circuits/ReLU.circom";
// include "./util.circom";
include "./utils/utils.circom";

// Depthwise Convolution layer with valid padding
// Note that nFilters must be a multiple of nChannels
// n = 10 to the power of the number of decimal places
template SeparableBNConvolution (nRows, nCols, nChannels, nDepthFilters, nPointFilters, n) {
    var kernelSize = 3;
    var strides = 1;

    // [running of hash outputted by the previous layer, hash of the activations of the previous layer]
    signal input in[nRows][nCols][nChannels];

    signal input dw_conv_weights[kernelSize][kernelSize][nDepthFilters]; // H x W x C x K
    signal input dw_conv_bias[nDepthFilters];
    signal input dw_conv_out[nRows][nCols][nDepthFilters];
    signal input dw_conv_remainder[nRows][nCols][nDepthFilters];

    signal input dw_bn_a[nDepthFilters];
    signal input dw_bn_b[nDepthFilters];
    signal input dw_bn_out[nRows][nCols][nDepthFilters];
    signal input dw_bn_remainder[nRows][nCols][nDepthFilters];

    // signal input pw_conv_weights[kernelSize][kernelSize][nPointFilters]; // H x W x C x K
    signal input pw_conv_weights[nDepthFilters][nPointFilters]; // weights are 2d because kernel_size is 1
    signal input pw_conv_bias[nPointFilters];
    signal input pw_conv_out[nRows][nCols][nPointFilters];
    signal input pw_conv_remainder[nRows][nCols][nPointFilters];

    signal input pw_bn_a[nPointFilters];
    signal input pw_bn_b[nPointFilters];
    signal input pw_bn_out[nRows][nCols][nPointFilters];
    signal input pw_bn_remainder[nRows][nCols][nPointFilters];

    log("START");
    component dw_conv = PaddedDepthwiseConv2D(nRows, nCols, nChannels, nDepthFilters, kernelSize, strides, 10**15);

    dw_conv.in <== in;
    dw_conv.weights <== dw_conv_weights;
    dw_conv.bias <== dw_conv_bias;
    dw_conv.out <== dw_conv_out;
    dw_conv.remainder <== dw_conv_remainder;
    log("dw_conv done");

    component dw_bn = PaddedBatchNormalization2D(nRows, nCols, nDepthFilters, n);
    dw_bn.in <== dw_conv_out;
    dw_bn.a <== dw_bn_a;
    dw_bn.b <== dw_bn_b;
    dw_bn.out <== dw_bn_out;
    dw_bn.remainder <== dw_bn_remainder;
    log("depth batch norm done");

    component pw_conv = PointwiseConv2D(nRows, nCols, nDepthFilters, nPointFilters, n);
    pw_conv.in <== dw_bn_out;
    pw_conv.weights <== pw_conv_weights;
    pw_conv.bias <== pw_conv_bias;
    pw_conv.out <== pw_conv_out;
    pw_conv.remainder <== pw_conv_remainder;
    log("pw_conv done");

    component pw_bn = PaddedBatchNormalization2D(nRows, nCols, nPointFilters, n);
    pw_bn.in <== pw_conv_out;
    pw_bn.a <== pw_bn_a;
    pw_bn.b <== pw_bn_b;
    pw_bn.out <== pw_bn_out;
    pw_bn.remainder <== pw_bn_remainder;
    log("point batch norm done");

    log("END");
}

// component main = SeparableBNConvolution(32, 32, 32, 32, 32, 10**15);
