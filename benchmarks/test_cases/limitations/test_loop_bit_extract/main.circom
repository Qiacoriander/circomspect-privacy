pragma circom 2.0.0;

template TestLiteral() {
    signal input in;
    signal output out;
    // Case 1: Simple Literal Shift
    // Expected: Leaks 1 bit (index 10)
    out <== (in >> 10) & 1;
}

template TestConstant() {
    signal input in;
    signal output out;
    // Case 2: Variable Constant Shift
    // Circom compiler usually folds this, but privacy analysis runs on IR. 
    // Is 's' visible as a constant in IR?
    var s = 5;
    // Expected: Leaks 1 bit (index 5)
    out <== (in >> s) & 1;
}

template TestLoop() {
    signal input in;
    signal output out;
    signal bits[8];
    // Case 3: Simple Loop
    // Expected: Leaks 8 bits (indices 0 to 7)
    var sum = 0;
    for (var i = 0; i < 8; i++) {
        // (in >> 0) & 1
        // (in >> 1) & 1 ...
        var b = (in >> i) & 1;
        sum += b;
    }
    out <== sum;
}

template TestNestedLoop() {
    signal input in;
    signal output out;
    
    // Case 4: Nested Loop with Complex Expression
    // Expected: Leaks 4 bits (indices 0, 1, 2, 3) theoretically.
    // i in 0..2, j in 0..2
    // Shift amounts:
    // i=0, j=0 => 0
    // i=0, j=1 => 1
    // i=1, j=0 => 2
    // i=1, j=1 => 3
    var sum = 0;
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < 2; j++) {
            // Shift amount is an expression involving two loop variables
            // This is the hardest case for static analysis without unrolling
            var shift = i * 2 + j;
            var b = (in >> shift) & 1;
            sum += b;
        }
    }
    out <== sum;
}

template Main() {
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;

    component c1 = TestLiteral();
    c1.in <== in1;
    out1 <== c1.out;

    component c2 = TestConstant();
    c2.in <== in2;
    out2 <== c2.out;

    component c3 = TestLoop();
    c3.in <== in3;
    out3 <== c3.out;

    component c4 = TestNestedLoop();
    c4.in <== in4;
    out4 <== c4.out;
}

component main = Main();
