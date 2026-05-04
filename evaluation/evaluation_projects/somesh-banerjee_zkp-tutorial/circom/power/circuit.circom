pragma circom 2.1.6;

// Input : array of length 2
// Output : a[0]^a[1] 


include "../node_modules/circomlib/circuits/comparators.circom";

template Pow(max) {
    signal input a[2];

    // pow[i] = a[0]**i, basically will store all the powers of a[0] from 0 to max
    signal pow[max];
    // equal[i] = 1 if i == a[1], 0 otherwise; that means only one of the equal[i] will be 1
    signal equal[max];
    // result[i] = pow[i] * equal[i] + result[i - 1]; since equal[i] will be 1 only once, this will be the final result
    signal result[max];

    pow[0] <== 1;
    equal[0] <== 0;
    result[0] <== 0;

    var i = 1;
    while (i < max) {
        equal[i] <== IsEqual()([i, a[1]]);        
        pow[i] <== pow[i - 1] * a[0];
        i++;
    }

    i = 1;
    while (i < max) {
        result[i] <== result[i - 1] + pow[i] * equal[i];
        i++;
    }

    // if a = [5, 2], then output = 0*5^0 + 0*5^1 + 1*5^2 + 0*5^3 + 0*5^4 + 0*5^5 + 0*5^6 + 0*5^7 + 0*5^8 + 0*5^9

    signal output c <== result[i - 1];
}

// the 10 means max power that can be calculated
component main = Pow(10);