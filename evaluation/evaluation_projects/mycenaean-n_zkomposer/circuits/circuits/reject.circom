pragma circom 2.0.0;
include "./transform.circom";
include "./removeairbubbles.circom";
include "./removecolumnswithleadingzero.circom";

template Reject(W,H) {
    signal input grid[W][H];
    signal input onOff;
    signal input color;
    signal output out[W][H];

    assert(onOff == 0 || onOff == 1);

    component transform = Transform(W,H);
    transform.grid <== grid;
    transform.onOff <== onOff;
    transform.inColor <== color;
    transform.outColor <== 0;

    component removeAirBubbles = RemoveAirBubbles(W,H);
    removeAirBubbles.grid <== transform.out;
    removeAirBubbles.onOff <== onOff;

    component removeColumnsWithLeadingZero = RemoveColumnsWithLeadingZero(W,H);
    removeColumnsWithLeadingZero.grid <== removeAirBubbles.out;
    removeColumnsWithLeadingZero.onOff <== onOff;

    out <== removeColumnsWithLeadingZero.out;
}
