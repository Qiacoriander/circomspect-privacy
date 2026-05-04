pragma circom 2.1.9;

include "key_expansion.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/gates.circom";
include "transformations.circom";
include "mix_columns.circom";

// Cipher Process
// nk: number of keys which can be 4, 6, 8
// AES 128, 192, 256 have 10, 12, 14 rounds.
// Input Block   Initial Round Key          Round Key             Final Round Key
//     │                │                       │                       │
//     ▼                ▼                       ▼                       ▼
//  ┌─────────┐    ┌──────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐
//  │ Block   │──► │   Add    │ │  Sub   │ │   Mix    │ │  Sub   │ │   Add    │
//  │         │    │  Round   │ │ Bytes  │ │ Columns  │ │ Bytes  │ │  Round   │
//  │         │    │   Key    │ │        │ │          │ │        │ │   Key    │
//  └─────────┘    └────┬─────┘ └───┬────┘ └────┬─────┘ └───┬────┘ └────┬─────┘
//                      │           │           │           │           │
//                      ▼           ▼           ▼           ▼           ▼
//                 ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
//                 │ Round 0 │ │ Round 1 │ │ Round 2 │ │ Round   │ │  Final  │
//                 │         │ │   to    │ │   to    │ │ Nr - 1  │ │  Round  │
//                 │         │ │ Nr - 2  │ │ Nr - 1  │ │         │ │         │
//                 └─────────┘ └─────────┘ └─────────┘ └─────────┘ └────┬────┘
//                                                                      │
//                                                                      ▼
//                                                                 Ciphertext

// @param nk: number of keys which can be 4, 6, 8
// @inputs block: 4x4 matrix representing the input block
// @inputs key: array of nk*4 bytes representing the key
// @outputs cipher: 4x4 matrix representing the output block
template Cipher(nk){
        assert(nk == 4 || nk == 6 || nk == 8 );
        signal input block[4][4];
        signal input key[nk * 4];
        signal output cipher[4][4];

        var nr = Rounds(nk);
        
        component keyExpansion = KeyExpansion(nk,nr);
        keyExpansion.key <== key;

        component addRoundKey[nr+1]; 
        component subBytes[nr];
        component shiftRows[nr];
        component mixColumns[nr-1];

        signal interBlock[nr][4][4];

        addRoundKey[0] = AddRoundKey();
        addRoundKey[0].state <== block;
        for (var i = 0; i < 4; i++) {
                addRoundKey[0].roundKey[i] <== keyExpansion.keyExpanded[i];
        }

        interBlock[0] <== addRoundKey[0].newState;
        for (var i = 1; i < nr; i++) {
                subBytes[i-1] = SubBlock();
                subBytes[i-1].state <== interBlock[i-1];

                shiftRows[i-1] = ShiftRows();
                shiftRows[i-1].state <== subBytes[i-1].newState;

                mixColumns[i-1] = MixColumns();
                mixColumns[i-1].state <== shiftRows[i-1].newState;

                addRoundKey[i] = AddRoundKey();
                addRoundKey[i].state <== mixColumns[i-1].out;
                 for (var j = 0; j < 4; j++) {
                        addRoundKey[i].roundKey[j] <== keyExpansion.keyExpanded[j + (i * 4)];
                }

                interBlock[i] <== addRoundKey[i].newState;
        }

        subBytes[nr-1] = SubBlock();
        subBytes[nr-1].state <== interBlock[nr-1];

        shiftRows[nr-1] = ShiftRows();
        shiftRows[nr-1].state <== subBytes[nr-1].newState;

        addRoundKey[nr] = AddRoundKey();
        addRoundKey[nr].state <== shiftRows[nr-1].newState;
        for (var i = 0; i < 4; i++) {
                addRoundKey[nr].roundKey[i] <== keyExpansion.keyExpanded[i + (nr * 4)];
        }

        cipher <== addRoundKey[nr].newState;
}

// @param nk: number of keys which can be 4, 6, 8
// @returns number of rounds
// AES 128, 192, 256 have 10, 12, 14 rounds.
function Rounds (nk) {
    if (nk == 4) {
       return 10;
    } else if (nk == 6) {
        return 12;
    } else {
        return 14;
    }
}