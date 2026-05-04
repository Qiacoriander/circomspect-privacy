pragma circom 2.1.4;

// Input : array of length 2 
// Output : 4*a[0]+4*a[1] using a forLoop

template ForLoop() {
    signal input a[2];

    var sum = 0;
    for (var i = 0; i <4; i++) {
        sum +=  a[0]+a[1];
    }

    signal output c <== sum;
}

component main = ForLoop();