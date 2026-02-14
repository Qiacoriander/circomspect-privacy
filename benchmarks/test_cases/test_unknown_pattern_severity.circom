template UnknownLoopBound() {
    signal input in;
    signal output out;
    
    // Pattern 1: Constant loop bound (Case 5)
    // Currently Circomspect fails to resolve 'n' as constant, triggering unknown bound fallback
    var n = 8;
    var sum = 0;
    for (var i = 0; i < n; i++) {
        sum += (in >> i) & 1; 
    }
    
    // Pattern 2: Unknown variable shift (Complex expression fallback)
    // Using a signal in shift amount should trigger the fallback
    signal input shift_amt;
    signal output out2;
    out2 <== (in >> shift_amt) & 1;

    out <== sum;
}

component main = UnknownLoopBound();
