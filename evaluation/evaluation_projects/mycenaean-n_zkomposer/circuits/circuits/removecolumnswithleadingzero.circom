pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/comparators.circom";

template RemoveColumnsWithLeadingZero(W,H) {
    signal input grid[W][H];
    signal input onOff;

    signal notZeroFirstPositionEven[W][H][H];    
    signal isZeroFirstPositionEven[W][H][H];    
    signal notZeroSecondPositionEven[W][H][H];    
    signal isZeroSecondPositionEven[W][H][H];

    signal notZeroFirstPositionOdd[W][H][H];    
    signal isZeroFirstPositionOdd[W][H][H];    
    signal notZeroSecondPositionOdd[W][H][H];    
    signal isZeroSecondPositionOdd[W][H][H];

    component isZeroEven[W][H];
    component isZeroOdd[W][H];

    signal  columnSortingEven[W][W][H];
    signal  columnSortingOdd[W][W][H];
    // columnSortingOdd[0] <== column;
    signal output out[W][H];

    assert(onOff == 0 || onOff == 1);

    columnSortingOdd[0] <== grid;
    // i = (h/2)+1
    for(var i = 1; i < 7; i++) {
        for(var j = 0; j < W; j+=2) {
            isZeroEven[i][j] = IsZero();
            isZeroEven[i][j].in <== columnSortingOdd[i-1][j][0] + (1 - onOff);
            var isZeroOutEven = isZeroEven[i][j].out;
            for(var k = 0; k < H; k++) {
                notZeroFirstPositionEven[i][j][k] <== (1 - isZeroOutEven) * columnSortingOdd[i-1][j][k];
                isZeroFirstPositionEven[i][j][k] <== isZeroOutEven * columnSortingOdd[i-1][j+1][k];

                notZeroSecondPositionEven[i][j][k] <== (1 - isZeroOutEven) * columnSortingOdd[i-1][j+1][k];
                isZeroSecondPositionEven[i][j][k] <== 0;

                columnSortingEven[i][j][k] <== notZeroFirstPositionEven[i][j][k] + isZeroFirstPositionEven[i][j][k];
                columnSortingEven[i][j+1][k] <== notZeroSecondPositionEven[i][j][k] + isZeroSecondPositionEven[i][j][k];
            }
        }

        for(var l = 1; l < W-1; l+=2) {
            isZeroOdd[i][l] = IsZero();
            isZeroOdd[i][l].in <== columnSortingEven[i][l][0] + (1 - onOff);
            var isZeroOutOdd = isZeroOdd[i][l].out;

            for(var m = 0; m < H; m++) {
                notZeroFirstPositionOdd[i][l][m] <== (1 - isZeroOutOdd) * columnSortingEven[i][l][m];
                isZeroFirstPositionOdd[i][l][m] <== isZeroOutOdd * columnSortingEven[i][l+1][m];

                notZeroSecondPositionOdd[i][l][m] <== (1 - isZeroOutOdd) * columnSortingEven[i][l+1][m];
                isZeroSecondPositionOdd[i][l][m] <== 0;

                columnSortingOdd[i][l][m] <== notZeroFirstPositionOdd[i][l][m] + isZeroFirstPositionOdd[i][l][m];
                columnSortingOdd[i][l+1][m] <== notZeroSecondPositionOdd[i][l][m] + isZeroSecondPositionOdd[i][l][m];
            }
        }
        columnSortingOdd[i][0] <== columnSortingEven[i][0];
        columnSortingOdd[i][W-1] <== columnSortingEven[i][W-1];
    }
    // (h/2)
    out <== columnSortingEven[6];
}
