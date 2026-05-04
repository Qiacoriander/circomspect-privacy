pragma circom 2.1.2;

include "../../circuits/ecdsa_nullifier.circom";

component main { public[ Tx, Ty, Ux, Uy ]} = ECDSANullifier();
