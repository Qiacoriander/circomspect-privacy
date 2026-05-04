// location.circom
pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";

/*
This circuit proves that a private point (userX, userY) is within a
publicly known circle, defined by (centerX, centerY) and maxDistanceSquared.
*/
template LocationCheck() {
    // Private inputs (Prover's secret coordinates)
    signal input userX;
    signal input userY;

    // Public inputs (Verifier's known zone)
    signal input centerX;
    signal input centerY;
    signal input maxDistanceSquared; // Use squared distance to avoid complex square roots

    // Calculate deltas
    signal deltaX;
    signal deltaY;
    deltaX <== userX - centerX;
    deltaY <== userY - centerY;

    // Calculate squared distance
    signal deltaXSquared;
    signal deltaYSquared;

    // Constraint 1: (deltaX * deltaX = deltaXSquared)
    deltaXSquared <== deltaX * deltaX;
    
    // Constraint 2: (deltaY * deltaY = deltaYSquared)
    deltaYSquared <== deltaY * deltaY;

    // Constraint 3: (deltaXSquared + deltaYSquared = actualDistanceSquared)
    signal actualDistanceSquared;
    actualDistanceSquared <== deltaXSquared + deltaYSquared;
    /*
    Now, we must constrain that actualDistanceSquared < maxDistanceSquared.
    We use the LessThan comparator from circomlib.
    We'll set the bit-size 'n' to 64, which allows for large coordinates.
    */
    
    // 1. Install circomlib: npm i circomlib
    // RIGHT
    
    // 2. Instantiate the comparator
    // We are checking if a 64-bit number is less than another 64-bit number
    component lt = LessThan(64);

    // 3. Pass the inputs to the comparator
    lt.in[0] <== actualDistanceSquared;
    lt.in[1] <== maxDistanceSquared;

    // 4. Constrain the output
    // We force the output to be 1 (true), which fails if actualDistanceSquared >= maxDistanceSquared
    1 === lt.out;
}

// Instantiate the main component
component main = LocationCheck();