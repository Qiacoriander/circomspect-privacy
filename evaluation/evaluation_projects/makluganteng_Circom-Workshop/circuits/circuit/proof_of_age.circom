pragma circom 2.0.0; 

include "../node_modules/circomlib/circuits/comparators.circom";

template AgeLimit() {
    // private input
    signal input age; 
    
    // public input
    signal input ageLimit;

    // true/false
    signal output out;

    // Ensure age is within allowable range (0 to 100)
    signal ageRangeCheck;
    ageRangeCheck <== LessThan(7)([age, 101]); // 101 as the upper limit to ensure age <= 100
    ageRangeCheck === 1; // This will enforce that age is less than or equal to 100

    // considering max age 255
    component greaterThan = GreaterThan(8); 
    greaterThan.in[0] <== age;
    greaterThan.in[1] <== ageLimit;

    out <== greaterThan.out;
}

component main {public [ageLimit]} = AgeLimit();
