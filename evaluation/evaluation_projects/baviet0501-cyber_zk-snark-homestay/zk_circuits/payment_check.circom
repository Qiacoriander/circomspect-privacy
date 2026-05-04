// zk_circuits/payment_check.circom
// Compatible with circom 0.5.x
// Payment commitment verification using SimpleHash (similar to auth.circom)
// Hides booking_total in proof, only sends commitment publicly

template SimpleHash() {
    signal input in;
    signal output out;
    
    // Simple hash: out = in^2 + in + 1 (mod p)
    // This is ZK-friendly and works with circom 0.5
    signal temp;
    temp <== in * in;
    out <== temp + in + 1;
}

template PaymentCommitment() {
    // Private Input: combined_input = booking_total * 1000000000 + salt
    // We combine booking_total and salt into one private input to avoid issues with multiple private inputs in circom 0.5.x
    // Frontend will compute: combined_input = booking_total * 1000000000 + salt
    signal private input combined_input;
    
    // Public Input: commitment - hash of (booking_total, salt)
    // This will appear as publicSignals[0] in the proof
    signal input commitment;
    
    // Hash the combined input
    component hasher = SimpleHash();
    hasher.in <== combined_input;
    
    // Constraint: Hash must equal public commitment
    // This ensures the commitment matches the computed hash
    commitment === hasher.out;
}

component main = PaymentCommitment();

