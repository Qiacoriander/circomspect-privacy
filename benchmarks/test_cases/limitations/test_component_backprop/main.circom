pragma circom 2.0.0;

template SubLeaker() {
    signal input s;
    signal output o;
    // Explicit leakage inside sub-component
    o <== (s >> 0) & 1;
}

template Main() {
    signal input secret;
    signal output out;
    
    component c = SubLeaker();
    // Leakage should be back-propagated to 'secret'
    c.s <== secret;
    out <== c.o;
}

component main = Main();
