pragma circom 2.1.4;
include "../node_modules/circomlib/circuits/pedersen.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "../node_modules/circomlib/circuits/gates.circom";


template VerifyRandM(d) {
    // public input 
    signal input publicKey[2];
    signal input R[d][2];
    signal input M[d][2];

    // public or private depends on Vote or Fund
    signal input votingPower;

    // private input 
    signal input r[d];
    signal input o[d];

    var baseX = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var baseY = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    var counter = 0;
    for (var i = 0; i < d; i++){
        counter += o[i];
    }
    
    counter === 1;

    component rBits[d];
    component oBits[d];
    component escalarMulrG[d];
    component escalarMulrPk[d];
    component escalarMulvG[d];
    component adders[d];
    
    for (var i = 0; i < d; i++){
        rBits[i] = Num2Bits(256);
        oBits[i] = Num2Bits(256);
        escalarMulrG[i] = EscalarMulAny(256);
        escalarMulrPk[i] = EscalarMulAny(256);
        escalarMulvG[i] = EscalarMulAny(256);
        rBits[i].in <== r[i];
        oBits[i].in <== o[i] * votingPower;
        escalarMulrG[i].p[0] <== baseX;
        escalarMulrG[i].p[1] <== baseY;
        escalarMulrPk[i].p[0] <== publicKey[0];
        escalarMulrPk[i].p[1] <== publicKey[1];
        escalarMulvG[i].p[0] <== baseX;
        escalarMulvG[i].p[1] <== baseY;
        for(var j = 0; j < 256; j++){
            escalarMulrG[i].e[j] <== rBits[i].out[j];
            escalarMulrPk[i].e[j] <== rBits[i].out[j];
            escalarMulvG[i].e[j] <== oBits[i].out[j];
        }

        escalarMulrG[i].out[0] === R[i][0];
        escalarMulrG[i].out[1] === R[i][1];

        adders[i] = BabyAdd();
        adders[i].x1 <== escalarMulvG[i].out[0];
        adders[i].y1 <== escalarMulvG[i].out[1];
        adders[i].x2 <== escalarMulrPk[i].out[0];
        adders[i].y2 <== escalarMulrPk[i].out[1];

        adders[i].xout === M[i][0];
        adders[i].yout === M[i][1];
    }
}

template CommitmentHasher(d){
    signal input nullifier;
    signal input idDAO[d];
    signal input votingPower;
    signal input o[d];

    signal output out;

    var id = 0;
    for (var i = 0; i < d; i++){
        id = id + o[i] * idDAO[i];
    }

    component commitmentHasher = Pedersen(768);
    component nullifierBits = Num2Bits(256);
    component idBits = Num2Bits(256);
    component votingPowerBits = Num2Bits(256);
    nullifierBits.in <== nullifier;
    idBits.in <-- id;
    votingPowerBits.in <== votingPower;

    for (var i = 0; i< 256; i++){
        commitmentHasher.in[i] <== nullifierBits.out[i];
        commitmentHasher.in[i + 256] <== idBits.out[i];
        commitmentHasher.in[i + 512] <== votingPowerBits.out[i];
    }

    out <== commitmentHasher.out[0];
}

template Fund(d){
    // public input
    signal input publicKey[2];
    signal input idDAO[d];
    signal input votingPower;
    signal input commitment;
    signal input R[d][2];
    signal input M[d][2];
    

    // private input
    signal input nullifier;
    signal input r[d];
    signal input o[d];

    component commitmentHasher = CommitmentHasher(d);
    commitmentHasher.nullifier <== nullifier;
    commitmentHasher.votingPower <== votingPower;
    for (var i = 0; i < d; i++){
        commitmentHasher.idDAO[i] <== idDAO[i];
        commitmentHasher.o[i] <== o[i];
    }

    commitmentHasher.out === commitment;

    component verifyRandM = VerifyRandM(d);
    verifyRandM.publicKey[0] <== publicKey[0];
    verifyRandM.publicKey[1] <== publicKey[1];
    verifyRandM.votingPower <== votingPower;
    for (var i = 0; i < d; i++){
        verifyRandM.r[i] <== r[i];
        verifyRandM.o[i] <== o[i];
        verifyRandM.R[i][0] <== R[i][0];
        verifyRandM.R[i][1] <== R[i][1];
        verifyRandM.M[i][0] <== M[i][0];
        verifyRandM.M[i][1] <== M[i][1];
    }
}

component main {public [publicKey, idDAO, votingPower, commitment, R, M]} = Fund(3);