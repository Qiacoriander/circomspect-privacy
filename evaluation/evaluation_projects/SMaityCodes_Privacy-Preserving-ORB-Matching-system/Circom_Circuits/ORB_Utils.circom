/**  ALL COPYRIGHTS RESERVED BY MANASA PJ & S MAITY **/  

pragma circom 2.0.0;
include "circomlib/circuits/poseidon.circom";

// Calculates quotient, reminder, can roundup quotient etc.

template IntDivision(){
	signal input a, b;  // dividend and divisor
	signal output q, r, q_rounded;
	if(b == 0) log("DIVISION BY ZERO EROORRRRRRR !!!");
	q <-- a \ b;
	r <-- a % b;
	a === b * q + r;
	
	component lt = LessThan(32);  // For 32-bit numbers
	lt.in[0] <== 2 * r;  
	lt.in[1] <== b;  
	signal isLte <== lt.out;  
	q_rounded <== q + (1-lt.out);
	// log("q = ", q, ", r = ", r, "r < 0.5?", isLte);	
}

// Binary to Decimal Converter

template Bin2Dec(n) {
    signal input in[n];     // Input array of bits
    signal temp[n+1];      // Decimal output

    temp[0] <== 0;
    for (var i = 0; i < n; i++) {
        // Ensure each input is a bit
        in[i] * (in[i] - 1) === 0;

        // out += in[i] * (2^i)
        temp[i+1] <== temp[i] + in[i] * (1 << i);
    }
    signal output out <== temp[n];
}





// Merkle Root Cacculator

template MerkleTree(levels) {
    signal input leaves[2**levels];
    signal output root;
    
    // Total hashers needed: (2^levels - 1)
    component hashers[2**levels - 1];
    
    // Initialize all hashers
    for (var i = 0; i < 2**levels - 1; i++) {
        hashers[i] = Poseidon(2);
    }
    
    // Connect leaves (bottom level)
    var leaf_hashers = 2**(levels-1);
    for (var i = 0; i < leaf_hashers; i++) {
        hashers[i].inputs[0] <== leaves[2*i];
        hashers[i].inputs[1] <== leaves[2*i+1];
    }
    
    // Connect internal nodes
    var nodes_processed = 0;
    var nodes_in_level = leaf_hashers / 2;
    
    while (nodes_in_level >= 1) {
        for (var i = 0; i < nodes_in_level; i++) {
            var parent_idx = leaf_hashers + nodes_processed + i;
            var left_child = nodes_processed * 2 + i * 2;
            var right_child = left_child + 1;
            
            hashers[parent_idx].inputs[0] <== hashers[left_child].out;
            hashers[parent_idx].inputs[1] <== hashers[right_child].out;
        }
        nodes_processed += nodes_in_level;
        nodes_in_level = nodes_in_level / 2;
    }
    
    // The root is the last hasher
    root <== hashers[2**levels - 2].out;
}

