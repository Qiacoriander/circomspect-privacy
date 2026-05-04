pragma circom 2.1.6;

include "node_modules/circomlib/circuits/comparators.circom";

template AverageWrong(n) {

    signal input in[n];
    signal denominator;
    signal output out;

    // sum up the input signals;
    for (var i = 0; i < n; i++) {
        sum += in[i];
    }

    // compute the denominator
    denominator_inv <-- 1 / n;
    
    // "force" the denominator to be equal to the inverse of n
    1 === denominator_inv * n; // this does not create a constraint!
    
    // sum / denominator
    out <== sum * denominator_inv;
}

component main  = AverageWrong(5);

/*
    Avg = sum(input_signals) / count
since we operating on modulo math:
    Avg = sum(input_signals) * inv(count)

When the above circuit is compiled, we get zero constraints.
`1 === denominator_inv * n` does not create a constraint

When comparing a signal (n) to a constant (denominator_inv), use the IsEqual component, not ===


Correct way:
*/

template Average(n) {

    signal input in[n];
    signal denominator_inv;
    signal output out;

    var sum;
    for (var i = 0; i < n; i++) {
        sum += in[i];
    }

    // compute the denominator
    denominator_inv <-- 1 / n;

    // constraint for inv
    component eq = IsEqual();
    eq.in[0] <== 1;
    eq.in[1] <== denominator_inv * n;

    out <== sum * denominator_inv;

}

component main  = Average(5);

/*
Now when we compute the R1CS, we see the sum is constrained to be the sum of the signals and the denominator is constrained to be the inverse of n.

```bash
The following thee constraints ensure denominator really is calculated properly.

[INFO]  snarkJS: [ 21888242871839275222246405745257275088548364400416034343698204186575808495616main.in[0] +21888242871839275222246405745257275088548364400416034343698204186575808495616main.in[1] +21888242871839275222246405745257275088548364400416034343698204186575808495616main.in[2] +21888242871839275222246405745257275088548364400416034343698204186575808495616main.in[3] +21888242871839275222246405745257275088548364400416034343698204186575808495616main.in[4] ] * [ main.denominator ] - [ 21888242871839275222246405745257275088548364400416034343698204186575808495616main.out ] = 0

[INFO]  snarkJS: [ 51 +21888242871839275222246405745257275088548364400416034343698204186575808495616main.denominator ] * [ main.eq.isz.inv ] - [ 1 +21888242871839275222246405745257275088548364400416034343698204186575808495616main.eq.out ] = 0

[INFO]  snarkJS: [ 51 +21888242871839275222246405745257275088548364400416034343698204186575808495616main.denominator ] * [ main.eq.out ] - [  ] = 0
```

*/

