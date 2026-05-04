pragma circom 2.0.0;

include "../../circuits/simple_rsa_verify_v2.circom";

component main{public [exp, sign, modulus, hashed]} = simple_RsaVerifyPkcs1v15_v2(64, 32, 17, 4);

