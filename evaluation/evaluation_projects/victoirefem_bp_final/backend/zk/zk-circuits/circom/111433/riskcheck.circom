pragma circom 2.1.0;

include "../templates/poseidon.circom";

template RiskCheck(n) {
    signal input riskCommitments[n];
    signal input pdata[n][2];

    component hashes[n];
    for (var i = 0; i < n; i++) {
        hashes[i] = Poseidon(2);
        hashes[i].inputs[0] <== pdata[i][0];
        hashes[i].inputs[1] <== pdata[i][1];
        hashes[i].out === riskCommitments[i];
    }
}

component main { public [riskCommitments] } = RiskCheck(1);
