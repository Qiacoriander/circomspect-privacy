pragma circom 2.1.1;

// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";
// include "../../../circuits/origDepthwiseConv2d.circom";
include "origDepthwiseConv2d.circom";
// include "PaddedDepthwiseConv2d.circom";
// include "PaddedBatchNormalization2D.circom";
// include "ReLU.circom";
// include "MiMC3D.circom";
// include "PointwiseConv2d.circom";

template Backbone () {
    var paddedInputSize = 7;
    var nChannels = 3;
    var kernelSize = 3;
    var nDepthFilters = 3;
    var nPointFilters = 6;
    var stride = 1;
    signal input step_in[2];

    signal output step_out[2];

    signal input in[paddedInputSize][paddedInputSize][nChannels];

    signal input dw_conv_weights[kernelSize][kernelSize][nDepthFilters]; // H x W x C x K
    signal input dw_conv_bias[nConvFilters];
    signal input dw_conv_out[paddedInputSize][paddedInputSize][nDepthFilters];
    signal input dw_conv_remainder[paddedInputSize][paddedInputSize][nDepthFilters];

    signal input pw_conv_weights[kernelSize][kernelSize][nPointFilters]; // H x W x C x K
    signal input pw_conv_bias[nPointFilters];
    signal input pw_conv_out[paddedInputSize][paddedInputSize][nPointFilters];
    signal input pw_conv_remainder[paddedInputSize][paddedInputSize][nPointFilters];
    
    // signal input dw_bn_a[nConvFilters]; // H x W x C x K
    // signal input dw_bn_b[nConvFilters];
    // signal input dw_bn_out[5][5][3];
    // signal input dw_bn_remainder[5][5][3];

    log("START");
    
    // component conv = DepthwiseConv2D(paddedInputSize, paddedInputSize, nChannels, nConvFilters, kernelSize, stride, 10**15);
    component conv = PaddedDepthwiseConv2D(7, 7, 3, 3, 10**15);

    conv.in <== in;
    conv.weights <== dw_conv_weights;
    conv.bias <== dw_conv_bias;
    conv.out <== dw_conv_out;
    conv.remainder <== dw_conv_remainder;

    // component bn = PaddedBatchNormalization2D(7, 7, 3, 10**15);
    // bn.in <== dw_conv_out;
    // bn.a <== dw_bn_a;
    // bn.b <== dw_bn_a;
    // bn.out <== dw_bn_out;
    // bn.remainder <== dw_bn_remainder;

    // component hasher = MiMC3D(7, 7, 3);

    step_out[0] <== step_in[0] + in[0][0][0];
    step_out[1] <== step_in[0] + step_in[1];
    log("step_out[0]", step_out[0]);
    log("step_out[1]", step_out[1]);
    log("END");
}

component main { public [step_in] } = Backbone();
// component main { public [step_in] } = Backbone(34, 34, 256, 256, 3, 1);
