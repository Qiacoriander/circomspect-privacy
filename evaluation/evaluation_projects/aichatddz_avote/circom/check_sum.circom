pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";

template Sum(n) {
    assert(n>1);
    signal input points[n][2];
    signal input sum[2];

    component babyAdd[n-1];
    babyAdd[0] = BabyAdd();
    babyAdd[0].x1 <== points[0][0];
    babyAdd[0].y1 <== points[0][1];
    babyAdd[0].x2 <== points[1][0];
    babyAdd[0].y2 <== points[1][1];
    
    for (var i = 2; i < n; i++) {
        babyAdd[i-1] = BabyAdd();
        babyAdd[i-1].x1 <== babyAdd[i-2].xout;
        babyAdd[i-1].y1 <== babyAdd[i-2].yout;
        babyAdd[i-1].x2 <== points[i][0];
        babyAdd[i-1].y2 <== points[i][1];
    }

    babyAdd[n-2].xout === sum[0];
    babyAdd[n-2].yout === sum[1];
}

component main {public [points, sum]} = Sum(32);