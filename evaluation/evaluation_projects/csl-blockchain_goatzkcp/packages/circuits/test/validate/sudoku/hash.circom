pragma circom 2.0.8;

include "../../delivery/ciminion_ks_poseidon.circom";
include "sudoku.circom";

// Main for Ciminion KS ENC + Poseidon HASH
template top() {
    signal input MK_0;
    signal input MK_1;
    signal input H;
    signal input S[140];
    signal output calculated_hash;

    component sudoku = Check(16, 4);

    var puzzl[256] = [0, 15, 0, 1, 0, 2, 10, 14, 12, 0, 0, 0, 0, 0, 0, 0, 0, 6, 3, 16, 12, 0, 8, 4, 14, 15, 1, 0, 2, 0, 0, 0, 14, 0, 9, 7, 11, 3, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 13, 2, 12, 0, 0, 0, 0, 6, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 14, 1, 11, 7, 3, 5, 10, 0, 0, 8, 0, 12, 3, 16, 0, 0, 2, 4, 0, 0, 0, 14, 7, 13, 0, 0, 5, 15, 11, 0, 5, 0, 0, 0, 0, 0, 0, 9, 4, 0, 0, 6, 0, 0, 0, 0, 0, 0, 13, 0, 16, 5, 15, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 1, 12, 0, 8, 3, 10, 11, 0, 15, 0, 2, 12, 0, 11, 0, 0, 14, 3, 5, 4, 0, 0, 0, 0, 9, 0, 6, 3, 0, 4, 0, 0, 13, 0, 0, 11, 9, 1, 0, 12, 16, 2, 0, 0, 10, 9, 0, 0, 0, 0, 0, 0, 12, 0, 8, 0, 6, 7, 12, 8, 0, 0, 16, 0, 0, 10, 0, 13, 0, 0, 0, 5, 0, 0, 5, 0, 0, 0, 3, 0, 4, 6, 0, 1, 15, 0, 0, 0, 0, 0, 0, 9, 1, 6, 0, 14, 0, 11, 0, 0, 2, 0, 0, 0, 10, 8, 0, 14, 0, 0, 0, 13, 9, 0, 4, 12, 11, 8, 0, 0, 2, 0];
    var solution[256];
    var index = 0;
    
    // Initialize the solution array
    for (var i = 0; i < 256; i++) {
        if (puzzl[i] == 0) {
            solution[i] = S[index];
            index++;
        } else {
            solution[i] = puzzl[i];
        }
    }
    
    // Properly initialize the 2D grid
    for (var i = 0; i < 16; i++) {
        for (var j = 0; j < 16; j++) {
            sudoku.solved_grid[i][j] <== solution[i*16 + j];
        }
    }

    component hash = Enc(70);

    hash.MK_0 <== MK_0;
    hash.MK_1 <== MK_1;
    for (var i = 0; i < 140; i++){
        hash.PT[i] <== solution[i];
    }

    calculated_hash <== hash.Out;
    
    // Uncomment this line to enforce the hash verification
    // H === hash.Out;
}

component main {public [MK_0, MK_1, H]} = top();