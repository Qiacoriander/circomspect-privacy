pragma circom 2.0.2;

include "../../circuits/ecdsa_orig.circom";

component main {public [privkey]} = ECDSAPrivToPub(64, 4);
