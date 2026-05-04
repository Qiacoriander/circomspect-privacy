pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom"; // For LessThan

// Template to calculate (in % p)
template Mod() {
    signal input in;
    signal input p;
    signal output out;

    // q is a signal that represents how many times p goes into in
    signal q;
    
    // Witness computation (not part of the constraint)
    q <-- in \ p; // Integer division in witness calculation
    out <-- in % p; // Modulo in witness calculation
    
    // Constraints for modulo operation
    in === q * p + out;
    
    // Ensure out is in the range [0, p-1]
    component lt = LessThan(252); // Assuming inputs fit in 252 bits
    lt.in[0] <== out;
    lt.in[1] <== p;
    lt.out === 1;
}

template Square() {
    signal input in;
    signal output out;
    
    out <== in * in;
}

template SquareSumMod() {
    // Private inputs
    signal input a;
    signal input b;
    
    // Public input
    signal input p; // Prime modulus
    
    // Public output
    signal output c;
    
    // Calculate a²
    component squareA = Square();
    squareA.in <== a;
    
    // Calculate b²
    component squareB = Square();
    squareB.in <== b;
    
    // Calculate a² + b²
    signal sumSquares;
    sumSquares <== squareA.out + squareB.out;
    
    // Calculate (a² + b²) % p
    component modulo = Mod();
    modulo.in <== sumSquares;
    modulo.p <== p;
    
    // Set the output
    c <== modulo.out;

    // Debug log - después de modular
    log("\n El resultado de ", a, "^2 +", b, "^2 mod ", p, " es ", c);
}

component main { public [p] } = SquareSumMod();

