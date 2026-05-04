pragma circom 2.0.0;

include "../../circuits/group_sig_rsa_verify_v2.circom";

component main{public [publicKeys, hashed]} = GroupRsaVerifyPkcs1v15_v2(64, 32, 17, 4, 5000);


