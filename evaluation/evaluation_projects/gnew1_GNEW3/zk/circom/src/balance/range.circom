pragma circom 2.1.6;

// RANGE PROOF: demuestra que el balance comprometido >= amount sin revelar el balance.
// Público: commitment C, amount
// Privado: balance, blinding
// Constraint: Poseidon(balance, blinding) == C && balance >= amount

include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";
include "circomlib/bitify.circom";

template RangeGE() {
    // public
    signal input C;
    signal input amount;
    // private
    signal input balance;
    signal input blinding;

    // hash
    component H = Poseidon(2);
    H.inputs[0] <== balance;
    H.inputs[1] <== blinding;
    H.out === C;

    // balance >= amount  <=>  !(amount > balance)
    component lt = LessThan(254);
    lt.in[0] <== amount;
    lt.in[1] <== balance;
    lt.out === 1;
}

component main = RangeGE();

