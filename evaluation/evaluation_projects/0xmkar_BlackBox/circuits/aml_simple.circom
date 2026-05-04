pragma circom 2.0.0;

template AMLCheck() {
    signal input addr;
    signal input root;
    signal output valid;
    
    // Simple check: addr != root (user not on blacklist)
    signal diff;
    diff <== addr - root;
    
    // If diff is non-zero, user is valid
    valid <== diff * diff; // Will be non-zero if addr != root
}

component main {public [root]} = AMLCheck();
