pragma circom 2.0.5;

include "./board/BoardVerifier.circom";

template Main() {
    signal input board[100];
    signal input coordinates[44];
    signal input boardHash[256];

    component verifier = BoardVerifier(); //add overlapping check
    for (var i = 0; i < 100; i++) {
        verifier.board[i] <== board[i];
    }
    for (var i = 0; i < 30; i++) {
        verifier.coordinates[i] <== coordinates[i];
    }
    for (var i = 0; i < 256; i++) {
        verifier.boardHash[i] <== boardHash[i];
    }

}

component main {public [boardHash]} = Main();