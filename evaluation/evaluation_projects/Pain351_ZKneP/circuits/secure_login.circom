pragma circom 2.0.0;
include "circomlib/circuits/comparators.circom";

template SecureLogin() {
    // Private inputs
    signal input passwordHash;
    signal input pin;
    signal input timestamp;
    
    // Public inputs
    signal input userId;
    signal input expectedPasswordHash;
    signal input expectedPin;
    signal input maxTimestamp;
    signal input authLevel;
    
    // Public outputs
    signal output isAuthenticated;
    
    // Verify password hash
    component passwordCheck = IsEqual();
    passwordCheck.in[0] <== passwordHash;
    passwordCheck.in[1] <== expectedPasswordHash;
    
    // Verify PIN
    component pinCheck = IsEqual();
    pinCheck.in[0] <== pin;
    pinCheck.in[1] <== expectedPin;
    
    // Verify timestamp is within range
    component timeCheck = LessEqThan(64);
    timeCheck.in[0] <== timestamp;
    timeCheck.in[1] <== maxTimestamp;
    
    component timeValidityCheck = GreaterThan(64);
    timeValidityCheck.in[0] <== timestamp;
    timeValidityCheck.in[1] <== maxTimestamp - 300; // 5 minute window
    
    // FIXED: Use intermediate signals to avoid quadratic constraints
    signal timeValid <== timeCheck.out * timeValidityCheck.out;
    
    // Authentication level checks (FIXED: Separate multiplications)
    component level1 = IsEqual();
    level1.in[0] <== authLevel;
    level1.in[1] <== 1;
    signal auth1 <== level1.out * passwordCheck.out;
    
    component level2 = IsEqual();
    level2.in[0] <== authLevel;
    level2.in[1] <== 2;
    
    // FIXED: Split the multiplication into steps
    signal passwordAndPin <== passwordCheck.out * pinCheck.out;
    signal auth2 <== level2.out * passwordAndPin;
    
    // Final authentication result
    signal authResult <== auth1 + auth2;
    isAuthenticated <== authResult * timeValid;
}

component main = SecureLogin();
