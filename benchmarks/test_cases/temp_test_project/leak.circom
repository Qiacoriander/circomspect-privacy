template Leak() {
    signal input s;
    signal output o[254];
    
    for (var i = 0; i < 254; i++) {
        o[i] <-- (s >> i) & 1;
        o[i] * (o[i] - 1) === 0;
    }
}
component main = Leak();
