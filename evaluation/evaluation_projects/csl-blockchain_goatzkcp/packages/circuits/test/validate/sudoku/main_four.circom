pragma circom 2.0.8;

include "../../delivery/ciminion_ks_poseidon_four.circom";
include "sudoku.circom";

// Main for Ciminion KS ENC + Poseidon HASH
template top() {
    signal input MK_0;
    signal input MK_1;
    signal input H;
    signal input S[10];

    component sudoku = Check(4, 2);

    var puzzl[16] = [
        0, 0, 0, 2,
        2, 0, 0, 4,
        3, 0, 0, 1,
        0, 0, 4, 0
    ];
    var solution[16];
    var index = 0;
    for (var i = 0; i < 16; i++) {
        if (puzzl[i] == 0) {
            solution[i] = S[index];
            index++;
        } else {
            solution[i] = puzzl[i];
        }
        sudoku.solved_grid[i\4][i%4] <== solution[i];
    }

    component hash = Enc(5);

    hash.MK_0 <== MK_0;
    hash.MK_1 <== MK_1;
    for (var i = 0; i < 10; i++){
        hash.PT[i] <== solution[i];
    }

    H === hash.Out;
}

component main {public [MK_0, MK_1]} = top();