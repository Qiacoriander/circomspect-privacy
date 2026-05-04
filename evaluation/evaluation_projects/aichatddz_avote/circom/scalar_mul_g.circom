pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/babyjub.circom";

template scalarMulG(n) {
    assert(n<253);
    signal input scalar;
    signal input point[2];

    signal isInRange <== LessThan(n)([scalar, 2736030358979909402780800718157159386076813972158567259200215660948447373041]);
    isInRange === 1;

    component d = Num2Bits(n);
    d.in <== scalar;

    component q = EscalarMulFix(n, [5299619240641551281634865583518297030282874472190772894086521144482721001553, 16950150798460657717958625567821834550301663161624707787222815936182638968203]);
    q.e <== d.out;
    q.out === point;
}

component main {public [scalar, point]} = scalarMulG(252);