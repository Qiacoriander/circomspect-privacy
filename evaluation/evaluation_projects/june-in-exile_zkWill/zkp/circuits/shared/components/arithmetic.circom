pragma circom 2.2.2;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/**
 * Example: Integer division with remainder
 *  signal quotient, remainder;
 *  (quotient,remainder) <== Divide(8,8)(17,5);
 *  quotient === 3;
 *  remainder === 2;
 */
template Divide() {
    signal input dividend;
    signal input divisor;
    signal output quotient;
    signal output remainder;

    quotient <-- dividend \ divisor;
    remainder <-- dividend % divisor;
    dividend === quotient * divisor + remainder;
}

/**
 * Mathematical operation: c[i] = a[i] × b[i] for all i in [0, n-1]
 * 
 * @param n - The length of the input and output arrays
 *
 * Example: Element-wise array multiplication
 *  signal products[4] = MultiplyTwoArray(4)([2, 3, 4, 5],[10, 20, 30, 40]);
 *  Results: [20, 60, 120, 200];
 */
template MultiplyTwoArray(n) {
    signal input a[n];
    signal input b[n];
    signal output c[n];

    for (var i = 0; i < n; i++) {
        c[i] <== a[i] * b[i];
    }
}


/**
 * Mathematical operation: out = in[0] + in[1] + in[2] + ... + in[n-1]
 * 
 * @param n - The number of input signals to sum (must be > 2)
 * 
 * Example: Adding 4 numbers
 *  signal result <== Adder(4)([10, 20, 30, 40]);
 *  result === 100;
 */
template Sum(n) {
    assert(n > 2);
    signal input in[n];
    signal output out;

    signal sum[n - 1];
    sum[0] <== in[0] + in[1];

    for (var i = 1; i < n - 1; i++) {
        sum[i] <== sum[i - 1] + in[i + 1];
    }

    out <== sum[n - 2];
}

/**
* @param in - The input number to check parity for
* @return out - The result: 0 if even, 1 if odd
* 
* Example:
*  signal parity <== Mod2()(7);   // Returns 1 (odd)
*  signal parity <== Mod2()(8);   // Returns 0 (even)
*/
template Mod2() {
    signal input in;
    signal output {bit} out;
    
    signal quotient;
    
    (quotient, out) <== Divide()(in, 2);
    
    out * (out - 1) === 0;
}