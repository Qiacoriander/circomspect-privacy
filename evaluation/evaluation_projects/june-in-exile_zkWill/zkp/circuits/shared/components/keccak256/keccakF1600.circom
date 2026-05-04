pragma circom 2.2.2;

include "circomlib/circuits/gates.circom";
include "../arithmetic.circom";
include "../bits.circom";

/**
 * Keccak256 θ (theta) step: Column parity computation
 *
 * XOR each bit in the state with the parities of two neighboring columns
 * Optimized by using modulo arithmetic instead of chained XOR gates
 */
template Theta() {
    signal input {bit} stateArray[5][5][64];
    signal output {bit} newStateArray[5][5][64];

    // Column sum computation: C[x,z] = A[x,0,z] + A[x,1,z] + A[x,2,z] + A[x,3,z] + A[x,4,z]
    signal C[5][64];
    signal columnValues[5][64][5];
    for (var x = 0; x < 5; x++) {
        for (var z = 0; z < 64; z++) {
            for (var y = 0; y < 5; y++) {
                columnValues[x][z][y] <== stateArray[x][y][z];
            }
            C[x][z] <== Sum(5)(columnValues[x][z]);
        }
    }
    
    signal D[5][64];
    for (var x = 0; x < 5; x++) {
        for (var z = 0; z < 64; z++) {
            // D computation: D[x,z] = C[(x-1) % 5, z] + C[(x+1) % 5, (z-1) % 64]
            D[x][z] <== C[(x + 4) % 5][z] + C[(x + 1) % 5][(z + 63) % 64];
            // A'[x,y,z] = (A[x,y,z] + D[x,z]) % 2
            for (var y = 0; y < 5; y++) {
                newStateArray[x][y][z] <== Mod2()(stateArray[x][y][z] + D[x][z]);
            }
        }
    }
}

/**
 * Keccak256 ρ (rho) step: Bit rotation
 * 
 * Rotate each lane by a predefined offset amount.
 */
template Rho() {
    signal input {bit} stateArray[5][5][64];
    signal output {bit} newStateArray[5][5][64];

    // ρ (rho) rotation offsets based on the official specification
    var RHO_OFFSETS[5][5] = [
        [  0,  36,   3, 105, 210],
        [  1, 300,  10,  45,  66],
        [190,   6, 171,  15, 253],
        [ 28,  55, 153,  21, 120],
        [ 91, 276, 231, 136,  78]
    ];

    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            var offset = RHO_OFFSETS[x][y] % 64;
            for (var z = 0; z < 64; z++) {
                newStateArray[x][y][z] <== stateArray[x][y][(z + 64 - offset) % 64];
            }
        }
    }
}

/**
* Keccak256 π (pi) step: Lane permutation
* 
* Rearranges the 25 lanes according to the formula: (x,y) → ((x + 3*y) % 5, x).
*/
template Pi() {
    signal input {bit} stateArray[5][5][64];
    signal output {bit} newStateArray[5][5][64];

    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            var temp_x = (x + 3 * y) % 5;
            var temp_y = x;
            for (var z = 0; z < 64; z++) {
                newStateArray[x][y][z] <== stateArray[temp_x][temp_y][z];
            }
        }
    }
}

/**
* Keccak256 χ (chi) step: Non-linear transformation
* 
* Applies the formula: A'[x,y,z] = A[x,y,z] ⊕ ((¬A[(x+1)%5,y,z]) ∧ A[(x+2)%5,y,z]).
* This is the only non-linear step in Keccak, providing confusion by mixing bits within each row.
*/
template Chi() {
    signal input {bit} stateArray[5][5][64];
    signal output {bit} newStateArray[5][5][64];

    signal {bit} notNext[5][5][64];
    signal {bit} andTerm[5][5][64];
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var z = 0; z < 64; z++) {
               notNext[x][y][z] <== 1 - stateArray[(x + 1) % 5][y][z];
               andTerm[x][y][z] <== notNext[x][y][z] * stateArray[(x + 2) % 5][y][z];
               newStateArray[x][y][z] <== XOR()(stateArray[x][y][z], andTerm[x][y][z]);
            }
        }
    }
}

/**
* Keccak256 ι (iota) step: Round constant addition
* 
* XORs the round constant with the first lane A[0,0] to break symmetry.
* Only affects lane (0,0), all other lanes remain unchanged.
*/
template Iota(round) {
    signal input {bit} stateArray[5][5][64];
    signal output {bit} newStateArray[5][5][64];

    // Keccak round constants (64-bit values)
    var roundConstantBits[24][64] = [
            [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x0000000000000001
            [0,1,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x0000000000008082
            [0,1,0,1,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x800000000000808a
            [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x8000000080008000
            [1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x000000000000808b
            [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x0000000080000001
            [1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x8000000080008081
            [1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x8000000000008009
            [0,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x000000000000008a
            [0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x0000000000000088
            [1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x0000000080008009
            [0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x000000008000000a
            [1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x000000008000808b
            [1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x800000000000008b
            [1,0,0,1,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x8000000000008089
            [1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x8000000000008003
            [0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x8000000000008002
            [0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x8000000000000080
            [0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x000000000000800a
            [0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x800000008000000a
            [1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x8000000080008081
            [0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 0x8000000000008080
            [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // 0x0000000080000001
            [0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]  // 0x8000000080008008
    ];

    // Copy all lanes unchanged except (0,0)
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            if (x == 0 && y == 0) {
                for (var z = 0; z < 64; z++){
                    newStateArray[x][y][z] <== XOR()(stateArray[x][y][z], roundConstantBits[round][z]);
                }
            } else {
                newStateArray[x][y] <== stateArray[x][y];
            }
        }
    }
}

/**
* Keccak-f[1600] permutation function
* 
* Applies 24 rounds of the 5-step Keccak transformation:
* θ (theta) → ρ (rho) → π (pi) → χ (chi) → ι (iota)
*/
template KeccakF1600() {
    signal input {bit} stateArray[5][5][64];
    signal output {bit} newStateArray[5][5][64];

    signal {bit} statesArray[25][5][5][64];
   
    statesArray[0] <== stateArray;

    signal {bit} stateArrayAfterTheta[24][5][5][64];
    signal {bit} stateArrayAfterRho[24][5][5][64];
    signal {bit} stateArrayAfterPi[24][5][5][64];
    signal {bit} stateArrayAfterChi[24][5][5][64];

    for (var round = 0; round < 24; round++) {
        
        // θ (theta) step
        stateArrayAfterTheta[round] <== Theta()(statesArray[round]);
        
        // ρ (rho) step
        stateArrayAfterRho[round] <== Rho()(stateArrayAfterTheta[round]);
        
        // π (pi) step
        stateArrayAfterPi[round] <== Pi()(stateArrayAfterRho[round]);
        
        // χ (chi) step
        stateArrayAfterChi[round] <== Chi()(stateArrayAfterPi[round]);
        
        // ι (iota) step
        statesArray[round + 1] <== Iota(round)(stateArrayAfterChi[round]);
    }

    newStateArray <== statesArray[24];
}
