pragma circom 2.0.0;


template HighLeakage() {
    signal input secret;
    signal output out[10];
    
    // Extract multiple bits using bit operations
    // Each bit extraction leaks 1 bit
    out[0] <-- secret & 1;         // bit 0
    out[1] <-- (secret >> 1) & 1;  // bit 1
    out[2] <-- (secret >> 2) & 1;  // bit 2
    out[3] <-- (secret >> 3) & 1;  // bit 3
    out[4] <-- (secret >> 4) & 1;  // bit 4
    out[5] <-- (secret >> 5) & 1;  // bit 5
    out[6] <-- (secret >> 6) & 1;  // bit 6
    out[7] <-- (secret >> 7) & 1;  // bit 7
    out[8] <-- (secret >> 8) & 1;  // bit 8
    out[9] <-- (secret >> 9) & 1;  // bit 9

}

component main = HighLeakage();

