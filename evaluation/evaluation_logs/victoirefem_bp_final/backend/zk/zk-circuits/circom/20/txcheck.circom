pragma circom 2.1.0;

include "../templates/poseidon.circom";

template TxCheck(n) {
    signal input txCommitments[n];
    signal input pdata[n][7];

    component hashes[n];
    for (var i = 0; i < n; i++) {
        hashes[i] = Poseidon(7);
        for (var j = 0; j < 7; j++) {
            hashes[i].inputs[j] <== pdata[i][j];
        }
        hashes[i].out === txCommitments[i];
    }
}

component main { public [txCommitments] } = TxCheck(6);
