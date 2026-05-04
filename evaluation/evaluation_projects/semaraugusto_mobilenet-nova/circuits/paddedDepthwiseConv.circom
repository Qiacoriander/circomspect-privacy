pragma circom 2.1.1;
// include "./Conv2D.circom";

include "./node_modules/circomlib/circuits/sign.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./node_modules/circomlib/circuits/comparators.circom";
include "./node_modules/circomlib-matrix/circuits/matElemMul.circom";
include "./node_modules/circomlib-matrix/circuits/matElemSum.circom";
include "./util.circom";

// Depthwise Convolution layer with valid padding
// Note that nFilters must be a multiple of nChannels
// n = 10 to the power of the number of decimal places
template PaddedDepthwiseConv2D (nRows, nCols, nChannels, nFilters, kernelSize, strides, n) {
    // var kernelSize = 3;
    // var strides = 1;
    var outRows = (nRows-kernelSize)\strides+1;
    var outCols = (nCols-kernelSize)\strides+1;

    signal input in[nRows][nCols][nChannels];
    signal input weights[kernelSize][kernelSize][nFilters]; // weights are 3d because depth is 1
    signal input bias[nFilters];
    signal input remainder[nRows][nCols][nFilters];

    signal input out[nRows][nCols][nFilters];

    component mul[outRows][outCols][nFilters];
    component elemSum[outRows][outCols][nFilters];

    var valid_groups = nFilters % nChannels;
    var filtersPerChannel = nFilters / nChannels;

    signal groups;
    groups <== valid_groups;
    component is_zero = IsZero();
    is_zero.in <== groups;
    is_zero.out === 1;

    // Can probably remove below loops using main loop instead
    // Checking if padding has been applied correctly on the columns (albeit walking along the rows and checking if them are 0)
    for (var row=0; row<nRows; row++) {
        // for (var filterMultiplier=1; filterMultiplier<=filtersPerChannel; filterMultiplier++) {
        //     for (var channel=0; channel<nChannels; channel++) {
        for (var filter=0; filter<nFilters; filter++) {
                // var filter = filterMultiplier*channel;
                out[row][0][filter] === 0;
                out[row][nCols-1][filter] === 0;

                remainder[row][0][filter] === 0;
                remainder[row][nCols-1][filter] === 0;
            }
    }
    // Checking if padding has been applied correctly on the rows (albeit walking along the columns and checking if them are 0)
    for (var col=0; col<nCols; col++) {
        for (var filter=0; filter<nFilters; filter++) {
                out[0][col][filter] === 0;
                out[nRows-1][col][filter] === 0;

                remainder[0][col][filter] === 0;
                remainder[nRows-1][col][filter] === 0;
            }
    }

    for (var row=0; row<outRows; row++) {
        for (var col=0; col<outCols; col++) {
            for (var filterMultiplier=1; filterMultiplier<=filtersPerChannel; filterMultiplier++) {
                for (var channel=0; channel<nChannels; channel++) {
                    var filter = filterMultiplier*channel;

                    mul[row][col][filter] = matElemMul(kernelSize,kernelSize);

                    for (var x=0; x<kernelSize; x++) {
                        for (var y=0; y<kernelSize; y++) {
                            mul[row][col][filter].a[x][y] <== in[row*strides+x][col*strides+y][channel];
                            mul[row][col][filter].b[x][y] <== weights[x][y][filter];
                        }
                    }

                    elemSum[row][col][filter] = matElemSum(kernelSize,kernelSize);
                    for (var x=0; x<kernelSize; x++) {
                        for (var y=0; y<kernelSize; y++) {
                            elemSum[row][col][filter].a[x][y] <== mul[row][col][filter].out[x][y];
                        }
                    }
                    assert (remainder[row+1][col+1][filter] < n);
                    out[row+1][col+1][filter] * n + remainder[row+1][col+1][filter] === elemSum[row][col][filter].out + bias[filter];
                }
            }
        }
    }
}

// component main = PaddedDepthwiseConv2D(7, 7, 3, 3, 3, 1, 10**15);
