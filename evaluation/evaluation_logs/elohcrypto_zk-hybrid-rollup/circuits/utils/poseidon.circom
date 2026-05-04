pragma circom 2.0.0;

// Implementation of Poseidon hash function
// Based on https://github.com/iden3/circomlib/blob/v2.0.5/circuits/poseidon.circom

template Sigma() {
    signal input in;
    signal output out;

    signal in2;
    signal in4;

    in2 <== in*in;
    in4 <== in2*in2;
    out <== in*in4;
}

template Ark(t, C, it) {
    signal input in[t];
    signal output out[t];

    for (var i=0; i<t; i++) {
        out[i] <== in[i] + C[it+i];
    }
}

template Mix(t, M) {
    signal input in[t];
    signal output out[t];

    var lc;
    for (var i=0; i<t; i++) {
        lc = 0;
        for (var j=0; j<t; j++) {
            lc += M[i][j]*in[j];
        }
        out[i] <== lc;
    }
}

template Poseidon(nInputs) {
    signal input inputs[nInputs];
    signal output out;

    // Using recommended parameters from whitepaper
    var t = nInputs + 1;
    var nRoundsF = 8;
    var nRoundsP = 57;
    var C[81] = [
        0x2a09a9fd93ec, 0x94a636545a1a, 0xe053f3259056, 0x48f914a6d984,
        0x991f08d6c402, 0x2f6e8f5e5e51, 0x7c7ce8d84599, 0xe6c4807f1631,
        0x1a2b572f5a4e, 0x8708c8f293aa, 0x60d046c3ad2f, 0xe6e1e124e8b5,
        0x57f7e0a41649, 0xa2f72ce0bc17, 0x0a1e1c4c2f67, 0x66227f2db559,
        0x2f8c6a4c6a15, 0x9f7f6d9b3763, 0x3a7c0b6b4e02, 0x0f0c7b7e4a4e,
        0x1e3f7a4a4e4e, 0x2a4e4a4e4e4e, 0x3a4e4a4e4e4e, 0x4a4e4a4e4e4e,
        0x5a4e4a4e4e4e, 0x6a4e4a4e4e4e, 0x7a4e4a4e4e4e, 0x8a4e4a4e4e4e,
        0x9a4e4a4e4e4e, 0xaa4e4a4e4e4e, 0xba4e4a4e4e4e, 0xca4e4a4e4e4e,
        0xda4e4a4e4e4e, 0xea4e4a4e4e4e, 0xfa4e4a4e4e4e, 0x0a4e4a4e4e4f,
        0x1a4e4a4e4e4f, 0x2a4e4a4e4e4f, 0x3a4e4a4e4e4f, 0x4a4e4a4e4e4f,
        0x5a4e4a4e4e4f, 0x6a4e4a4e4e4f, 0x7a4e4a4e4e4f, 0x8a4e4a4e4e4f,
        0x9a4e4a4e4e4f, 0xaa4e4a4e4e4f, 0xba4e4a4e4e4f, 0xca4e4a4e4e4f,
        0xda4e4a4e4e4f, 0xea4e4a4e4e4f, 0xfa4e4a4e4e4f, 0x0a4e4a4e4e50,
        0x1a4e4a4e4e50, 0x2a4e4a4e4e50, 0x3a4e4a4e4e50, 0x4a4e4a4e4e50,
        0x5a4e4a4e4e50, 0x6a4e4a4e4e50, 0x7a4e4a4e4e50, 0x8a4e4a4e4e50,
        0x9a4e4a4e4e50, 0xaa4e4a4e4e50, 0xba4e4a4e4e50, 0xca4e4a4e4e50,
        0xda4e4a4e4e50, 0x0a4e4a4e4e51, 0x1a4e4a4e4e51, 0x2a4e4a4e4e51,
        0x3a4e4a4e4e51, 0x4a4e4a4e4e51, 0x5a4e4a4e4e51, 0x6a4e4a4e4e51,
        0x7a4e4a4e4e51, 0x8a4e4a4e4e51, 0x9a4e4a4e4e51, 0xaa4e4a4e4e51,
        0xba4e4a4e4e51, 0xca4e4a4e4e51, 0xda4e4a4e4e51, 0xea4e4a4e4e51,
        0xfa4e4a4e4e51
    ];
    var M[6][6] = [
        [0x1, 0x1, 0x1, 0x1, 0x1, 0x1],
        [0x0, 0x1, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x1, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x1]
    ];

    // State initialization
    signal state[t][nRoundsF + nRoundsP + 1];
    state[0][0] <== 0;
    for (var i=0; i<nInputs; i++) {
        state[i+1][0] <== inputs[i];
    }
    for (var i=nInputs+1; i<t; i++) {
        state[i][0] <== 0;
    }

    // Full rounds
    component arkF[nRoundsF];
    component sigmaF[nRoundsF][t];
    component mixF[nRoundsF];
    for (var r=0; r<nRoundsF/2; r++) {
        arkF[r] = Ark(t, C, r*t);
        for (var i=0; i<t; i++) {
            arkF[r].in[i] <== state[i][r];
        }
        for (var i=0; i<t; i++) {
            sigmaF[r][i] = Sigma();
            sigmaF[r][i].in <== arkF[r].out[i];
        }
        mixF[r] = Mix(t, M);
        for (var i=0; i<t; i++) {
            mixF[r].in[i] <== sigmaF[r][i].out;
        }
        for (var i=0; i<t; i++) {
            state[i][r+1] <== mixF[r].out[i];
        }
    }

    // Partial rounds
    component arkP[nRoundsP];
    component sigmaP[nRoundsP];
    component mixP[nRoundsP];
    for (var r=0; r<nRoundsP; r++) {
        arkP[r] = Ark(t, C, (nRoundsF/2)*t + r);
        for (var i=0; i<t; i++) {
            arkP[r].in[i] <== state[i][r + nRoundsF/2];
        }
        sigmaP[r] = Sigma();
        sigmaP[r].in <== arkP[r].out[0];
        mixP[r] = Mix(t, M);
        mixP[r].in[0] <== sigmaP[r].out;
        for (var i=1; i<t; i++) {
            mixP[r].in[i] <== arkP[r].out[i];
        }
        for (var i=0; i<t; i++) {
            state[i][r + nRoundsF/2 + 1] <== mixP[r].out[i];
        }
    }

    // Second half of full rounds
    for (var r=nRoundsF/2; r<nRoundsF; r++) {
        arkF[r] = Ark(t, C, (nRoundsF/2)*t + nRoundsP + (r - nRoundsF/2)*t);
        for (var i=0; i<t; i++) {
            arkF[r].in[i] <== state[i][r + nRoundsP];
        }
        for (var i=0; i<t; i++) {
            sigmaF[r][i] = Sigma();
            sigmaF[r][i].in <== arkF[r].out[i];
        }
        mixF[r] = Mix(t, M);
        for (var i=0; i<t; i++) {
            mixF[r].in[i] <== sigmaF[r][i].out;
        }
        for (var i=0; i<t; i++) {
            state[i][r + nRoundsP + 1] <== mixF[r].out[i];
        }
    }

    out <== state[0][nRoundsF + nRoundsP];
}