pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "../node_modules/circomlib/circuits/gates.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";

template InvModJubSuborder() {
    signal input in;
    
    signal output out;

    var jubSuborder = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    var t = 0;
    var newT = 1;
    var r = jubSuborder;
    var newR = in;
    var q;
    var tmp;
    while(newR != 0){
        q = r \ newR;
        tmp = newT;
        newT = (t + (jubSuborder - (q * newT) % jubSuborder) )% jubSuborder;
        t = tmp;
        tmp = newR;
        newR = r - q * newR;
        r = tmp;
    }
    out <-- t;
}

template LagrangeCoefficient(t) {
    signal input in[t];

    signal output out[t];
    var jubSuborder = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    component inv[t];
    // out[0] <-- 912010119659969800926933572719053128692271324052855753066738553649482457683;
    // out[1] <-- 2736030358979909402780800718157159386076813972158567259200215660948447373039;
    // out[2] <-- 1824020239319939601853867145438106257384542648105711506133477107298964915361;

    for(var indexI = 0 ; indexI < t; indexI++){
        var i = in[indexI];
        var numerator = 1;
        var denominator = 1;
        var negativeCounter = 0;
        for(var indexJ = 0; indexJ < t; indexJ++){
            var j = in[indexJ];
            if(i != j){
                numerator = numerator * j;
                if(j < i){
                    negativeCounter += 1;
                    denominator = denominator * (i - j);
                } else {
                    denominator = denominator * (j - i);
                }
            }
        }
        if(negativeCounter % 2 == 1){
            denominator = jubSuborder - denominator;
        }
        inv[indexI] = InvModJubSuborder();
        inv[indexI].in <-- denominator;
        denominator = inv[indexI].out;
        out[indexI] <-- (numerator * denominator)%jubSuborder;
    }
}

template ResultVerifier (d, t, n) {
    
    // public input
    signal input lagrangeCoefficient[t];
    signal input D[t][d][2];
    signal input M[d][2];
    signal input result[d];
    // signal input resultVector[d][2];

    var baseX = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var baseY = 16950150798460657717958625567821834550301663161624707787222815936182638968203;
    var field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    component lagrangeCoefficientBits[t];
    for(var i = 0; i < t; i++){
        lagrangeCoefficientBits[i] = Num2Bits(256);
        lagrangeCoefficientBits[i].in <== lagrangeCoefficient[i];
    }

    var sumDx[d];
    var sumDy[d];
    for(var i = 0; i < d; i++){
        sumDx[i] = 0;
        sumDy[i] = 1;
    }
    component escalarMulD[t][d];
    component sumDAdders[t][d];
    for(var i = 0; i < t; i++){
        for(var j = 0; j < d; j++){
            escalarMulD[i][j] = EscalarMulAny(256);
            escalarMulD[i][j].p[0] <== D[i][j][0];
            escalarMulD[i][j].p[1] <== D[i][j][1];
            for(var k = 0; k < 256; k++){
                escalarMulD[i][j].e[k] <== lagrangeCoefficientBits[i].out[k];
            }
            sumDAdders[i][j] = BabyAdd();
            sumDAdders[i][j].x1 <== sumDx[j];
            sumDAdders[i][j].y1 <== sumDy[j];
            sumDAdders[i][j].x2 <== escalarMulD[i][j].out[0];
            sumDAdders[i][j].y2 <== escalarMulD[i][j].out[1];
            sumDx[j] = sumDAdders[i][j].xout;
            sumDy[j] = sumDAdders[i][j].yout;
        }
    }

    component resultVectorAdders[d];
    for(var i = 0; i < d; i++){
        sumDx[i] = field - sumDx[i];
        resultVectorAdders[i] = BabyAdd();
        resultVectorAdders[i].x1 <== sumDx[i];
        resultVectorAdders[i].y1 <== sumDy[i];
        resultVectorAdders[i].x2 <== M[i][0];
        resultVectorAdders[i].y2 <== M[i][1];

        sumDx[i] = resultVectorAdders[i].xout;
        sumDy[i] = resultVectorAdders[i].yout;
        // resultVector[i][0] === sumDx[i];
        // resultVector[i][1] === sumDy[i];
    }

    component escalarMul[d];
    component resultBits[d];
    for(var i = 0; i < d; i++){
        resultBits[i] = Num2Bits(256);
        resultBits[i].in <== result[i];
        escalarMul[i] = EscalarMulAny(256);
        escalarMul[i].p[0] <== baseX;
        escalarMul[i].p[1] <== baseY;
        for (var j = 0; j < 256; j++){
            escalarMul[i].e[j] <== resultBits[i].out[j];
        }

        escalarMul[i].out[0] === sumDx[i];
        escalarMul[i].out[1] === sumDy[i];
    }
}

component main {public [lagrangeCoefficient, D, M, result]} = ResultVerifier(3,3,5);