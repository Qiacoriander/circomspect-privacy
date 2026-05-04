pragma circom 2.1.6;

// Input : single int
// Output : if the input is in the range [1, 9]

// we will try to do this withouth using any library

// next power of 2 >= 9(our upper bound) is 16 i.e. 2^4
// so we will check if the (input + 6) and (input - 1) are 4-bit numbers 

// ensure that the input is a 4-bit number
template Bits4(){
    signal input in;
    signal bits[4];
    var bitsum = 0;
    for (var i = 0; i < 4; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        bitsum = bitsum + 2 ** i * bits[i];
    }
    bitsum === in;
    signal output out <== bitsum;
}

// Enforce that 1 <= in <= 9
template Range() {
    signal input a;
    component lowerBound = Bits4();
    component upperBound = Bits4();
    lowerBound.in <== a - 1;
    upperBound.in <== a + 6;

    signal output out <== lowerBound.out * upperBound.out;
}

component main = Range();