pragma circom 2.1.3;
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template BidRangeCommit() {
    // Private inputs: the bid and a random salt (blinding factor)
    signal input bid;
    signal input salt;
    
    // Public inputs: minimum and maximum allowed bid values.
    signal input minBid;
    
    // Ensure bid is at least minBid.
    component ltMin = LessThan(250);
    ltMin.in[0] <== bid;
    ltMin.in[1] <== minBid;
    // If bid < minBid, ltMin.out is 1; enforce that ltMin.out == 0
    ltMin.out === 0;

    // Compute the commitment using Poseidon.
    // The commitment = Poseidon(bid, salt)
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== bid;
    poseidon.inputs[1] <== salt;
    signal output commitment;
    commitment <== poseidon.out;
}

component main = BidRangeCommit();