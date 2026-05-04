pragma circom 2.0.8;

include "../../delivery/ciminion_wks_poseidon_four.circom";
include "sudoku.circom";

// Main for Ciminion KS ENC + Poseidon HASH
template top() {
    signal input Keys[13];
    signal input H;
    signal input S[10];
    signal output calculated_hash;

    component sudoku = Check(4, 2);

    var puzzl[16] = [
        0, 0, 0, 2,
        2, 0, 0, 4,
        3, 0, 0, 1,
        0, 0, 4, 0
    ];
    var solution[16];
    var index = 0;
    
    // Initialize the solution array
    for (var i = 0; i < 16; i++) {
        if (puzzl[i] == 0) {
            solution[i] = S[index];
            index++;
        } else {
            solution[i] = puzzl[i];
        }
    }
    
    // Properly initialize the 2D grid
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 4; j++) {
            sudoku.solved_grid[i][j] <== solution[i*4 + j];
        }
    }

    component hash = Enc(5);

    for (var i = 0; i < 16; i++){
        hash.Keys[i] <== Keys[i];
    }

    for (var i = 0; i < 10; i++){
        hash.PT[i] <== solution[i];
    }
    calculated_hash <== hash.Out;
    
    // Uncomment this line to enforce the hash verification
    // H === hash.Out;
}

component main {public [Keys, H]} = top();