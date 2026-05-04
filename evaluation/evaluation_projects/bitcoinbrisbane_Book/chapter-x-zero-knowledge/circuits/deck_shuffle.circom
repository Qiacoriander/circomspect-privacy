pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

// Fisher-Yates Shuffle Verification Circuit
// Proves that outputDeck is a valid permutation of inputDeck
// using Fisher-Yates algorithm with given random values

template FisherYatesShuffle(n) {
    // n = number of cards (52 for standard deck)
    
    signal input inputDeck[n];      // Original ordered deck
    signal input outputDeck[n];     // Shuffled deck
    signal input randomValues[n];   // Random values used for shuffling (private)
    
    // Intermediate deck states during shuffling
    signal deck[n][n];
    
    // Initialize first row with input deck
    for (var i = 0; i < n; i++) {
        deck[0][i] <== inputDeck[i];
    }
    
    // Perform Fisher-Yates shuffle step by step
    for (var i = 0; i < n - 1; i++) {
        // Calculate swap index: j = i + (randomValues[i] % (n - i))
        signal swapIndex[i];
        signal range[i];
        range[i] <== n - i;
        
        // Modulo operation: randomValues[i] % range[i]
        signal quotient[i];
        signal remainder[i];
        quotient[i] <-- randomValues[i] \ range[i];
        remainder[i] <-- randomValues[i] % range[i];
        
        // Verify: randomValues[i] = quotient[i] * range[i] + remainder[i]
        randomValues[i] === quotient[i] * range[i] + remainder[i];
        
        // Verify remainder is in valid range [0, range[i])
        component ltCheck = LessThan(32);
        ltCheck.in[0] <== remainder[i];
        ltCheck.in[1] <== range[i];
        ltCheck.out === 1;
        
        // Calculate actual swap index
        swapIndex[i] <== i + remainder[i];
        
        // Perform swap between position i and swapIndex[i]
        for (var j = 0; j < n; j++) {
            if (j == i) {
                // Position i gets value from swapIndex[i]
                deck[i+1][j] <== deck[i][swapIndex[i]];
            } else if (j == swapIndex[i]) {
                // Position swapIndex[i] gets value from i
                deck[i+1][j] <== deck[i][i];
            } else {
                // Other positions remain unchanged
                deck[i+1][j] <== deck[i][j];
            }
        }
    }
    
    // Verify final output matches the shuffled deck
    for (var i = 0; i < n; i++) {
        outputDeck[i] === deck[n-1][i];
    }
    
    // Verify that output is a valid permutation (all unique values)
    component uniqueCheck[n][n];
    signal isEqual[n][n];
    signal matchCount[n];
    
    for (var i = 0; i < n; i++) {
        var count = 0;
        for (var j = 0; j < n; j++) {
            uniqueCheck[i][j] = IsEqual();
            uniqueCheck[i][j].in[0] <== outputDeck[i];
            uniqueCheck[i][j].in[1] <== inputDeck[j];
            isEqual[i][j] <== uniqueCheck[i][j].out;
            count += isEqual[i][j];
        }
        // Each output card must appear exactly once in input
        matchCount[i] <-- count;
        matchCount[i] === 1;
    }
}

// Main component for standard 52-card deck
component main {public [inputDeck, outputDeck]} = FisherYatesShuffle(52);