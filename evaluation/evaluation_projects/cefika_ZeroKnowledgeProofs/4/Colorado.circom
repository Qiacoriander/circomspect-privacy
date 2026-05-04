pragma circom 2.1.6;

include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";

// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

template Example (N) {
    assert(N <= 252);
    signal input sgs;   // (0 - 90)
    signal input zgd;  // (0 - 180)
    signal input addressHash;
    signal input commitment;
    signal input salt;

    signal output isValid;

    signal input sgsMin;
    signal input sgsMax;
    signal input zgdMin;
    signal input zgdMax;
    
    component addressHashCheck = Poseidon(2);
    addressHashCheck.inputs[0] <== addressHash;
    addressHashCheck.inputs[1] <== salt;
    component isEqualCommitment = IsEqual();
    isEqualCommitment.in[0] <== commitment;
    isEqualCommitment.in[1] <== addressHashCheck.out;

    component sgs_ValidLower = GreaterEqThan(N);
    component sgs_ValidUpper = LessEqThan(N);
    component zgd_ValidLower = GreaterEqThan(N);
    component zgd_ValidUpper = LessEqThan(N);

    // sgs >= sgsMin
    sgs_ValidLower.in[0] <== sgs;
    sgs_ValidLower.in[1] <== sgsMin;

    // sgs <= sgsMax
    sgs_ValidUpper.in[0] <== sgs;
    sgs_ValidUpper.in[1] <== sgsMax;

    // zgd >= zgdMin
    zgd_ValidLower.in[0] <== zgd;
    zgd_ValidLower.in[1] <== zgdMin;

    // zgd <= zgdMax
    zgd_ValidUpper.in[0] <== zgd;
    zgd_ValidUpper.in[1] <== zgdMax;

    signal temp1;
    signal temp2;

    temp1 <== sgs_ValidLower.out * sgs_ValidUpper.out;
    temp2 <== zgd_ValidLower.out * zgd_ValidUpper.out;

    isValid <==  temp1 * temp1;

}

component main { public [ commitment,sgsMin,sgsMax,zgdMin,zgdMax ] } = Example(252);

/* INPUT = {
    "sgs": "37",
    "zgd": "105",
     "salt": "578789985645456879678",
    "addressHash": "1234567890123456789012345678901234567890123456789012345678901234",
    "commitment": "18290756784816207199976835344004633283990028741082068901014247095738035526578",
    "sgsMin": "37",
    "sgsMax": "41",
    "zgdMin": "102",
    "zgdMax": "109"

} */