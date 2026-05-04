pragma circom 2.1.1;

include "./node_modules/circomlib-ml/circuits/Conv2D.circom";
include "./node_modules/circomlib-ml/circuits/BatchNormalization2D.circom";
include "./node_modules/circomlib-ml/circuits/ReLU.circom";
// include "./ReLU.circom";

template MultiReLU(inputSize, nFilters) {
    signal input in[inputSize][inputSize][nFilters];
    signal input out[inputSize][inputSize][nFilters];
    signal output ok;

    component relu[inputSize][inputSize][nFilters];

    for (var row=0; row < inputSize; row++) {
        for (var col=0; col < inputSize; col++) {
            for(var filter=0; filter < nFilters; filter++) {
                relu[row][col][filter] = ReLU();
                relu[row][col][filter].in <== in[row][col][filter];
                relu[row][col][filter].out <== out[row][col][filter];
            }
        }
    }
    ok <== 1;
}

template Head(n) {
    // H x W x C
    var inputSize = 32;
    var paddedInputSize = 34;
    var nChannels = 3;
    var nConvFilters = 1;
    var kernelSize = 3;

    signal input in[paddedInputSize][paddedInputSize][nChannels];

    // Initial Layer: Conv2D + BN + RELU
    signal input conv2d_weights[kernelSize][kernelSize][nChannels][nConvFilters]; // H x W x C x K
    signal input conv2d_bias[nConvFilters];
    signal input conv2d_out[inputSize][inputSize][nConvFilters];
    signal input conv2d_remainder[inputSize][inputSize][nConvFilters];

    signal input bn_a[nConvFilters];
    signal input bn_b[nConvFilters];
    signal input bn_out[inputSize][inputSize][nConvFilters];
    signal input bn_remainder[inputSize][inputSize][nConvFilters];

    signal input relu_out[inputSize][inputSize][nConvFilters];

    signal output out;
    log("something");

    // Start Initial Layer: Conv2D + BN + RELU
    // START INITIAL CONV 2D
    var stride = 1;
    component conv2d = Conv2D(paddedInputSize, paddedInputSize, nChannels, nConvFilters, kernelSize, stride, n);

    log("before conv2d");
    conv2d.in <== in;
    conv2d.weights <== conv2d_weights;
    conv2d.bias <== conv2d_bias;
    conv2d.out <== conv2d_out;
    conv2d.remainder <== conv2d_remainder;
    log("after conv2d");
    // START INITIAL BATCH NORM 2D 
    component bn = BatchNormalization2D(inputSize, inputSize, nConvFilters, n);
    bn.in <== conv2d_out;
    bn.a <== bn_a;
    bn.b <== bn_b;
    bn.out <== bn_out;
    bn.remainder <== bn_remainder;
    log("after bn");
    // START INITIAL RELU
    component multi_relu = MultiReLU(inputSize, nConvFilters);
    multi_relu.in <== bn_out;
    multi_relu.out <== relu_out;
    multi_relu.ok === 1;

    log("after relu");
    out <== 1; 
    log("end");
}

component main = Head(10**15);
