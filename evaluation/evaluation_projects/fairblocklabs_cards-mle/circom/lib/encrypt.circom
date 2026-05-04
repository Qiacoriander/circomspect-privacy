// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

pragma circom 2.1.9;

include "../common/elgamal.circom";
include "../common/matrix.circom";
include "../common/permutation.circom";
include "../common/babyjubjub.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

/**
 * @title ShuffleAndEncrypt
 * @dev Unified template for shuffle and encrypt operations with support for compressed points
 * 
 * This template implements the complete shuffle-encrypt algorithm:
 * 1. Handles compressed elliptic curve points (x, s, delta format)
 * 2. Decompresses points to full coordinates
 * 3. Validates permutation matrix
 * 4. Performs matrix multiplication for shuffling
 * 5. Applies ElGamal encryption to each card
 * 6. Validates output matches expected compressed format
 * 
 * @param base Base point for ElGamal encryption
 * @param numCards Number of cards in the deck
 * @param numBits Bit length for scalar field operations
 */
template ShuffleAndEncrypt(base, numCards, numBits) {
    assert(numCards <= 253);  // Ensure numCards fits in field element
    
    // ===== PUBLIC INPUTS =====
    signal input pk[2];                 // Public key for ElGamal encryption
    signal input UX0[numCards];         // X-coordinates of input deck (first component)
    signal input UX1[numCards];         // X-coordinates of input deck (second component)
    signal input VX0[numCards];         // X-coordinates of output deck (first component)
    signal input VX1[numCards];         // X-coordinates of output deck (second component)
    
    // ===== PRIVATE INPUTS =====
    signal input UDelta0[numCards];     // Delta values for input decompression (first component)
    signal input UDelta1[numCards];     // Delta values for input decompression (second component)
    signal input VDelta0[numCards];     // Delta values for output decompression (first component)
    signal input VDelta1[numCards];     // Delta values for output decompression (second component)
    signal input s_u[2];                // Selector bits for input y-coordinate recovery
    signal input s_v[2];                // Selector bits for output y-coordinate recovery
    signal input A[numCards*numCards];  // Permutation matrix (defines card shuffling order)
    signal input R[numCards];           // Random values for ElGamal encryption (one per card)
    
    // ===== INTERNAL SIGNALS =====
    signal B[4*numCards];               // Intermediate shuffled deck (before encryption)
    
    // ===== CONVERT SELECTOR BITS TO ARRAYS =====
    // Convert selector values to bit arrays for point decompression
    component n2b_u0 = Num2Bits(numCards);
    component n2b_u1 = Num2Bits(numCards);
    component n2b_v0 = Num2Bits(numCards);
    component n2b_v1 = Num2Bits(numCards);
    n2b_u0.in <== s_u[0];  // First component selector for input deck
    n2b_u1.in <== s_u[1];  // Second component selector for input deck
    n2b_v0.in <== s_v[0];  // First component selector for output deck
    n2b_v1.in <== s_v[1];  // Second component selector for output deck
    
    // ===== POINT DECOMPRESSION =====
    // Decompress all input and output points from compressed format
    component decompress[4*numCards];
    
    // Decompress input deck first component
    for (var i = 0; i < numCards; i++) {
        decompress[i] = BabyDecompress();
        decompress[i].x <== UX0[i];           // X-coordinate
        decompress[i].s <== n2b_u0.out[i];    // Selector bit
        decompress[i].delta <== UDelta0[i];   // Delta value
    }
    
    // Decompress input deck second component
    for (var i = 0; i < numCards; i++) {
        decompress[numCards + i] = BabyDecompress();
        decompress[numCards + i].x <== UX1[i];           // X-coordinate
        decompress[numCards + i].s <== n2b_u1.out[i];    // Selector bit
        decompress[numCards + i].delta <== UDelta1[i];   // Delta value
    }
    
    // Decompress output deck first component
    for (var i = 0; i < numCards; i++) {
        decompress[2*numCards + i] = BabyDecompress();
        decompress[2*numCards + i].x <== VX0[i];           // X-coordinate
        decompress[2*numCards + i].s <== n2b_v0.out[i];    // Selector bit
        decompress[2*numCards + i].delta <== VDelta0[i];   // Delta value
    }
    
    // Decompress output deck second component
    for (var i = 0; i < numCards; i++) {
        decompress[3*numCards + i] = BabyDecompress();
        decompress[3*numCards + i].x <== VX1[i];           // X-coordinate
        decompress[3*numCards + i].s <== n2b_v1.out[i];    // Selector bit
        decompress[3*numCards + i].delta <== VDelta1[i];   // Delta value
    }
    
    // ===== VALIDATE PERMUTATION MATRIX =====
    component permutation = Permutation(numCards);
    for (var i = 0; i < numCards*numCards; i++) {
        permutation.in[i] <== A[i];
    }
    
    // ===== SHUFFLE OPERATION (Matrix Multiplication) =====
    // Apply permutation matrix to each component of the deck
    component shuffle[4];
    for (var i = 0; i < 4; i++) {
        shuffle[i] = matrixMultiplication(numCards, numCards);
        
        // Set permutation matrix
        for (var j = 0; j < numCards*numCards; j++) {
            shuffle[i].A[j] <== A[j];
        }
        
        // Set input deck component (using decompressed points)
        for (var j = 0; j < numCards; j++) {
            if (i == 0) {
                shuffle[i].X[j] <== UX0[j];                    // First component x
            } else if (i == 1) {
                shuffle[i].X[j] <== decompress[j].y;           // First component y (decompressed)
            } else if (i == 2) {
                shuffle[i].X[j] <== UX1[j];                    // Second component x
            } else {
                shuffle[i].X[j] <== decompress[numCards + j].y; // Second component y (decompressed)
            }
        }
        
        // Get shuffled deck component
        for (var j = 0; j < numCards; j++) {
            B[i*numCards + j] <== shuffle[i].B[j];
        }
    }
    
    // ===== ENCRYPT OPERATION (ElGamal Encryption) =====
    // Encrypt each card in the shuffled deck
    component elgamal[numCards];
    for (var i = 0; i < numCards; i++) {
        elgamal[i] = ElGamalEncrypt(numBits, base);
        
        // Set card components (two group elements per card)
        elgamal[i].ic0[0] <== B[i];                    // First component x-coordinate
        elgamal[i].ic0[1] <== B[numCards + i];         // First component y-coordinate
        elgamal[i].ic1[0] <== B[2*numCards + i];       // Second component x-coordinate
        elgamal[i].ic1[1] <== B[3*numCards + i];       // Second component y-coordinate
        
        // Set encryption parameters
        elgamal[i].r <== R[i];                         // Random value for this card
        elgamal[i].pk[0] <== pk[0];                    // Public key x-coordinate
        elgamal[i].pk[1] <== pk[1];                    // Public key y-coordinate
    }
    
    // ===== VALIDATE OUTPUT =====
    // Verify that shuffle-encrypt output matches expected compressed format
    for (var i = 0; i < numCards; i++) {
        elgamal[i].c0[0] === VX0[i];                    // First component x
        elgamal[i].c0[1] === decompress[2*numCards + i].y; // First component y
        elgamal[i].c1[0] === VX1[i];                    // Second component x
        elgamal[i].c1[1] === decompress[3*numCards + i].y; // Second component y
    }
}