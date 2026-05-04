pragma circom 2.0.5;

include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/comparators.circom";


//C10001020304B001020304S1010203D0010203P00110

template ValidateCoordinates() {

    signal input coordinates[44];
    signal output valid[4][5];

    // Check if the coordinates are in the good format: ship letter + 1 (vertical) or 0 (horizontal) + coords + next ship, ship order: CBSDP
    coordinates[0] === 67; //C
    coordinates[1] === 0 || 1;
    coordinates[12] === 66; //B
    coordinates[13] === 0 || 1;
    coordinates[22] === 83; //S
    coordinates[23] === 0 || 1;
    coordinates[30] === 68; //D
    coordinates[31] === 0 || 1;
    coordinates[38] === 80; //P
    coordinates[39] === 0 || 1;

    // Check if coordinates are in the grid.

    component cmp[44];

    for (var i=0; i < 44; i++){
        cmp[i] = LessThan(8);
    }
    
    for (var i=0; i < 44; i++){

        if ((0) << i & ( (1 << 0) | (1 << 1) | (1 << 12) | (1 << 13) | (1 << 22) | (1 << 23) | (1 << 30) | (1 << 31) | (1 << 38) | (1 << 39) ) ) {
            cmp[i].in[0] <== coordinates[i];
            cmp[i].in[1] <== 10;
            cmp[i].out === 1;
        }
    }
}

template BoardVerifier() {

    signal input board[100];
    signal input coordinates[30];
    signal input boardHash[256];
    signal output computedHash[256];

    // Validate the inputs

    // -- Check that the coordinates are valid
    component validateCoordinates = ValidateCoordinates();

    for (var i=0; i < 30; i++){
        validateCoordinates.coordinates[i] <== coordinates[i];
    }

    // Compute the hash of the board and check it is the same as the one provided
    component SHA = Sha256(100);

    for (var i=0; i < 100; i++){
        SHA.in[i] <== board[i];
    }
    for (var i=0; i < 256; i++){
        SHA.out[i] ==> computedHash[i];
    }
    for (var i=0; i < 256; i++){
        computedHash[i] === boardHash[i];
    }

}