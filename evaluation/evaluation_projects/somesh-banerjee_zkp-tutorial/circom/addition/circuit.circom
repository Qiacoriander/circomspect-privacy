pragma circom 2.1.4;

// Input : array of length 2
// Output : sum of the elements of the array

template ForLoop() {
    signal input a[2];

    signal output c <== a[0]+a[1];
}

component main = ForLoop();