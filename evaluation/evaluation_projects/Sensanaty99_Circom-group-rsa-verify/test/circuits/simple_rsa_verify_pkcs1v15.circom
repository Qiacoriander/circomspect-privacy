pragma circom 2.0.0;

include "../../circuits/simple_rsa_verify.circom";

component main{public [exp, sign, modulus, hashed]} = simple_RsaVerifyPkcs1v15(64, 32, 17, 4);

