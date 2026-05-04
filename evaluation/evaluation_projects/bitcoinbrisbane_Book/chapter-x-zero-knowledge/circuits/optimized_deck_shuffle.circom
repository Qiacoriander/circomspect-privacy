pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";

/**
 * OPTIMIZED DECK SHUFFLE CIRCUIT
 * 
 * This version includes:
 * - More efficient constraint usage
 * - Commitment scheme for privacy
 * - Better randomness handling
 */

// ==================== HELPER TEMPLATES ====================

template Swap() {
    signal input arr[2];
    signal input doSwap; // 1 to swap, 0 to keep
    signal output out[2];
    
    // If doSwap = 1: out[0] = arr[1], out[1] = arr[0]
    // If doSwap = 0: out[0] = arr[0], out[1] = arr[1]
    out[0] <== arr[0] + doSwap * (arr[1] - arr[0]);
    out[1] <== arr[1] + doSwap * (arr[0] - arr[1]);
}

template SafeModulo() {
    signal input dividend;
    signal input divisor;
    signal output quotient;
    signal output remainder;
    
    // Calculate quotient and remainder
    quotient <-- dividend \ divisor;
    remainder <-- dividend % divisor;
    
    // Verify: dividend = quotient * divisor + remainder
    dividend === quotient * divisor + remainder;
    
    // Verify: 0 <= remainder < divisor
    component lt = LessThan(252);
    lt.in[0] <== remainder;
    lt.in[1] <== divisor;
    lt.out === 1;
}

// ==================== PERMUTATION CHECK ====================

template IsPermutation(n) {
    signal input arr[n];
    signal input reference[n];
    
    // Create frequency count for both arrays
    signal freq1[n][n];
    signal freq2[n][n];
    
    // Count occurrences in arr
    for (var i = 0; i < n; i++) {
        for (var j = 0; j < n; j++) {
            component eq1 = IsEqual();
            eq1.in[0] <== arr[i];
            eq1.in[1] <== j;
            if (i == 0) {
                freq1[i][j] <== eq1.out;
            } else {
                freq1[i][j] <== freq1[i-1][j] + eq1.out;
            }
        }
    }
    
    // Count occurrences in reference
    for (var i = 0; i < n; i++) {
        for (var j = 0; j < n; j++) {
            component eq2 = IsEqual();
            eq2.in[0] <== reference[i];
            eq2.in[1] <== j;
            if (i == 0) {
                freq2[i][j] <== eq2.out;
            } else {
                freq2[i][j] <== freq2[i-1][j] + eq2.out;
            }
        }
    }
    
    // Verify frequencies match
    for (var j = 0; j < n; j++) {
        freq1[n-1][j] === freq2[n-1][j];
    }
}

// ==================== MAIN SHUFFLE CIRCUIT ====================

template OptimizedFisherYatesShuffle(n) {
    // Public inputs
    signal input inputDeck[n];
    signal input outputDeck[n];
    signal input deckCommitment; // Poseidon hash of shuffled deck
    
    // Private inputs
    signal input randomSeed;
    signal input randomValues[n-1];
    
    // Verify the commitment
    component hasher = Poseidon(n + 1);
    hasher.inputs[0] <== randomSeed;
    for (var i = 0; i < n; i++) {
        hasher.inputs[i + 1] <== outputDeck[i];
    }
    hasher.out === deckCommitment;
    
    // Intermediate shuffle states
    signal deck[n][n];
    
    // Initialize with input deck
    for (var i = 0; i < n; i++) {
        deck[0][i] <== inputDeck[i];
    }
    
    // Perform Fisher-Yates shuffle with constraint optimization
    component modulo[n-1];
    signal swapIndices[n-1];
    
    for (var step = 0; step < n - 1; step++) {
        // Calculate modulo: randomValues[step] % (n - step)
        modulo[step] = SafeModulo();
        modulo[step].dividend <== randomValues[step];
        modulo[step].divisor <== n - step;
        
        // Swap index = step + (randomValues[step] % (n - step))
        swapIndices[step] <== step + modulo[step].remainder;
        
        // Perform conditional swaps for all positions
        for (var pos = 0; pos < n; pos++) {
            if (pos <= step) {
                // Positions before step are already fixed
                deck[step + 1][pos] <== deck[step][pos];
            } else {
                // Check if this position is involved in swap
                component eqStep = IsEqual();
                eqStep.in[0] <== pos;
                eqStep.in[1] <== step;
                
                component eqSwap = IsEqual();
                eqSwap.in[0] <== pos;
                eqSwap.in[1] <== swapIndices[step];
                
                // Determine new value for this position
                signal isSwapPos <== eqSwap.out;
                signal notSwapPos <== 1 - isSwapPos;
                
                // If pos == swapIndices[step]: take value from step
                // Otherwise: keep current value
                deck[step + 1][pos] <== 
                    notSwapPos * deck[step][pos] + 
                    isSwapPos * deck[step][step];
                
                // Handle the step position
                if (pos == step) {
                    deck[step + 1][step] <== deck[step][swapIndices[step]];
                }
            }
        }
    }
    
    // Verify output matches final shuffle state
    for (var i = 0; i < n; i++) {
        outputDeck[i] === deck[n-1][i];
    }
    
    // Verify output is a valid permutation of input
    component permCheck = IsPermutation(n);
    for (var i = 0; i < n; i++) {
        permCheck.arr[i] <== outputDeck[i];
        permCheck.reference[i] <== inputDeck[i];
    }
}

// ==================== DECK SHUFFLE WITH COMMITMENT ====================

template DeckShuffleWithCommitment(n) {
    // Public signals
    signal input inputDeck[n];
    signal input deckCommitment; // Public commitment to shuffled deck
    
    // Private signals
    signal input outputDeck[n];
    signal input randomSeed;
    signal input randomValues[n-1];
    
    // Verify shuffle
    component shuffle = OptimizedFisherYatesShuffle(n);
    
    for (var i = 0; i < n; i++) {
        shuffle.inputDeck[i] <== inputDeck[i];
        shuffle.outputDeck[i] <== outputDeck[i];
    }
    
    shuffle.deckCommitment <== deckCommitment;
    shuffle.randomSeed <== randomSeed;
    
    for (var i = 0; i < n - 1; i++) {
        shuffle.randomValues[i] <== randomValues[i];
    }
}

// ==================== MAIN COMPONENTS ====================

// For full deck verification (more constraints but complete proof)
component main {public [inputDeck, outputDeck]} = OptimizedFisherYatesShuffle(52);

// Alternative: commitment-based (fewer public inputs, more private)
// Uncomment to use this version instead:
// component main {public [inputDeck, deckCommitment]} = DeckShuffleWithCommitment(52);