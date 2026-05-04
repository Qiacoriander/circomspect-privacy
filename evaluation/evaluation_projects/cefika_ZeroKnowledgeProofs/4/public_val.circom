pragma circom 2.1.6;

include "circomlib/poseidon.circom";
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

template Example () {
    signal input a;
    signal input b;
    signal input c;
    signal input d;
    signal input e;
    signal input publicValue;

    signal pom1;
    signal pom2;
    signal pom3;

    pom1 <== a * b;
    pom2 <== pom1 * c;
    pom3 <== pom2 * d;
    publicValue === pom3 * e;
}

component main { public [ publicValue ] } = Example();

/* INPUT = {
    "a": "1",
    "b": "2",
    "c": "3",
    "d": "4",
    "e": "10",
    "publicValue": "240"
} */
