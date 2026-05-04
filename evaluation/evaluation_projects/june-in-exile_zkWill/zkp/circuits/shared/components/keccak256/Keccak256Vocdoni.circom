pragma circom 2.2.2;

include "keccak256-circom/circuits/keccak.circom";

/**
 * Uses the implementation of keccak256-circom as comparison:
 *  - GitHub: https://github.com/vocdoni/keccak256-circom
 *  - More constraint: 138170 ~ 152560 per block (our version: 115200 ~ 116288 per block)
 *  - Cannot hash multiple blocks
 */
template Keccak256Vocdoni(nBitsIn) {
    signal input msg[nBitsIn];
    signal output digest[256];

    digest <== Keccak(nBitsIn, 256)(msg);
}
