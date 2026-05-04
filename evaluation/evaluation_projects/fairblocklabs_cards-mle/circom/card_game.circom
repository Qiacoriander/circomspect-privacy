// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

pragma circom 2.1.9;

include "./lib/encrypt.circom";

/**
 * @title CardGame
 * @dev Main circuit for shuffle and encrypt operations on a deck of cards
 * 
 * This circuit implements the core shuffle-encrypt functionality for secure card games:
 * 1. Shuffles cards using a permutation matrix
 * 2. Encrypts each card using ElGamal encryption
 * 3. Uses compressed elliptic curve points for efficiency
 * 4. Provides zero-knowledge proof of correct shuffling and encryption
 * 
 * This circuit can be used for various card games requiring secure, verifiable shuffling
 * such as mental poker, secure card dealing, and other privacy-preserving card games.
 * 
 * @param numCards Number of cards in the deck (e.g., 52 for standard deck, 32 for reduced deck)
 */
template CardGame(numCards) {
    // Cryptographic parameters
    var numBits = 251;  // Bit length for scalar field operations
    
    // Base8 generator point of Baby JubJub curve
    // Reference: https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js#L18-L21
    var base[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    
    // ===== PUBLIC INPUTS (visible in proof) =====
    signal input pk[2];                 // Public key for ElGamal encryption (aggregated from all players)
    signal input UX0[numCards];         // X-coordinates of input deck (first component)
    signal input UX1[numCards];         // X-coordinates of input deck (second component)
    signal input VX0[numCards];         // X-coordinates of output deck (first component)
    signal input VX1[numCards];         // X-coordinates of output deck (second component)
    signal input s_u[2];                // Selector bits for y-coordinate recovery (input deck)
    signal input s_v[2];                // Selector bits for y-coordinate recovery (output deck)
    
    // ===== PRIVATE INPUTS (hidden in proof) =====
    signal input UDelta0[numCards];     // Delta values for input deck decompression (first component)
    signal input UDelta1[numCards];     // Delta values for input deck decompression (second component)
    signal input VDelta0[numCards];     // Delta values for output deck decompression (first component)
    signal input VDelta1[numCards];     // Delta values for output deck decompression (second component)
    signal input A[numCards*numCards];  // Permutation matrix (defines card shuffling order)
    signal input R[numCards];           // Random values for ElGamal encryption (one per card)
    
    // ===== OUTPUTS =====
    // Circom requires at least 1 output signal, so we create a dummy output
    signal output dummy_output;
    dummy_output <== pk[0] * pk[1];  // Simple computation to satisfy output requirement
    
    // ===== MAIN SHUFFLE-ENCRYPT COMPONENT =====
    component shuffle_encrypt = ShuffleAndEncrypt(base, numCards, numBits);
    
    // Connect public key
    shuffle_encrypt.pk[0] <== pk[0];
    shuffle_encrypt.pk[1] <== pk[1];
    
    // Connect input deck coordinates (X-coordinates and delta values)
    for (var i = 0; i < numCards; i++) {
        // First component of each card
        shuffle_encrypt.UX0[i] <== UX0[i];           // X-coordinate
        shuffle_encrypt.UDelta0[i] <== UDelta0[i];   // Delta for y-coordinate recovery
        
        // Second component of each card
        shuffle_encrypt.UX1[i] <== UX1[i];           // X-coordinate
        shuffle_encrypt.UDelta1[i] <== UDelta1[i];   // Delta for y-coordinate recovery
        
        // Output deck coordinates (expected results)
        shuffle_encrypt.VX0[i] <== VX0[i];           // X-coordinate
        shuffle_encrypt.VDelta0[i] <== VDelta0[i];   // Delta for y-coordinate recovery
        
        shuffle_encrypt.VX1[i] <== VX1[i];           // X-coordinate
        shuffle_encrypt.VDelta1[i] <== VDelta1[i];   // Delta for y-coordinate recovery
    }
    
    // Connect selector bits for y-coordinate recovery
    for (var i = 0; i < 2; i++) {
        shuffle_encrypt.s_u[i] <== s_u[i];  // Selectors for input deck
        shuffle_encrypt.s_v[i] <== s_v[i];  // Selectors for output deck
    }
    
    // Connect permutation matrix (defines how cards are shuffled)
    for (var i = 0; i < numCards * numCards; i++) {
        shuffle_encrypt.A[i] <== A[i];
    }
    
    // Connect random values for ElGamal encryption
    for (var i = 0; i < numCards; i++) {
        shuffle_encrypt.R[i] <== R[i];
    }
}

// ===== MAIN COMPONENT INSTANTIATION =====
// Public inputs: pk, UX0, UX1, VX0, VX1, s_u, s_v
// Private inputs: UDelta0, UDelta1, VDelta0, VDelta1, A, R
component main {public [pk, UX0, UX1, VX0, VX1, s_u, s_v]} = CardGame(52);