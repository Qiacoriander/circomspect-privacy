pragma circom 2.0.0;
include "./removecolumnswithleadingzero.circom";

template Filter(W,H) {
    signal input grid[W][H];
    signal input color;
    signal input onOff;
    signal counter[W][H];
    signal gridWithLeadingZero[W][H];
    // hackish
    signal coloring <== (onOff * color) - (1 - onOff);
    signal output out[W][H];

    assert(onOff == 0 || onOff == 1);

    component isEq[W][H];
    component isZero[H];
    for (var i = 0; i < W; i++) {
        isEq[i][0] = IsEqual();
        isEq[i][0].in[0] <== coloring;
        isEq[i][0].in[1] <== grid[i][0];
        counter[i][0] <== isEq[i][0].out;

        for (var j = 1; j < H; j++) {
            isEq[i][j] = IsEqual();
            isEq[i][j].in[0] <== coloring;
            isEq[i][j].in[1] <== grid[i][j];
            counter[i][j] <== counter[i][j-1] + isEq[i][j].out;
            gridWithLeadingZero[i][j] <== grid[i][j];
        }
        isZero[i] = IsZero();
        isZero[i].in <== counter[i][H-1];
        gridWithLeadingZero[i][0] <== isZero[i].out * grid[i][0];
    }

    component removeColumnsWithLeadingZero = RemoveColumnsWithLeadingZero(W,H);
    removeColumnsWithLeadingZero.grid <== gridWithLeadingZero;
    removeColumnsWithLeadingZero.onOff <== onOff;

    out <== removeColumnsWithLeadingZero.out;
}
