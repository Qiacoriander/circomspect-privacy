pragma circom 2.0.0;

// include "./node_modules/circomlib/circuits/compconstant.circom";
// include "./node_modules/circomlib/circuits/switcher.circom";
include "./node_modules/circomlib/circuits/comparators.circom";
include "./node_modules/circomlib/circuits/mux1.circom";

// BatchNormalization layer for 2D inputs
// a = gamma/(moving_var+epsilon)**.5
// b = beta-gamma*moving_mean/(moving_var+epsilon)**.5
// n = 10 to the power of the number of decimal places
template PaddedBatchNormalization2D(nRows, nCols, nChannels, n) {
    // log("STARTING BATCH NORM ---------------------------------------");
    signal input in[nRows][nCols][nChannels];
    signal input a[nChannels];
    signal input b[nChannels];
    signal input out[nRows][nCols][nChannels];
    signal input remainder[nRows][nCols][nChannels];

    component is_equal[nRows][nCols][nChannels];
    component muxes[nRows][nCols][nChannels];
    for (var i=0; i<nRows; i++) {
        for (var j=0; j<nCols; j++) {
            for (var k=0; k<nChannels; k++) {
                assert(remainder[i][j][k] <= n);
                // log("at: ", i, ", ", j, ", ", k);
                // log("remainder: ", remainder[i][j][k]);
                is_equal[i][j][k] = IsEqual();
                is_equal[i][j][k].in[0] <== remainder[i][j][k];
                is_equal[i][j][k].in[1] <== n;

                muxes[i][j][k] = Mux1();
                muxes[i][j][k].c[0] <== a[k]*in[i][j][k]+b[k];
                muxes[i][j][k].c[1] <== n;
                muxes[i][j][k].s <== is_equal[i][j][k].out;

                // log("LEFT  SIDE: ", out[i][j][k] * n + remainder[i][j][k]);
                // log("RIGHT SIDE: ", muxes[i][j][k].out);
                out[i][j][k] * n + remainder[i][j][k] === muxes[i][j][k].out;
            }
        }
    }
    // log("END BATCH NORM --------------------------------------------");
}

// component main { public [ out ] } = BatchNormalization2D(1, 1, 1, 1000);

/* INPUT = {
    "in":  ["123"],
    "a": ["234"],
    "b": ["345678"],
    "out": ["374"],
    "remainder": ["460"]
} */
