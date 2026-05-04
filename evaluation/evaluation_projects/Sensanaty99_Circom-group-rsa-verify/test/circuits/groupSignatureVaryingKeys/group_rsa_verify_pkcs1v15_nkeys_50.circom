pragma circom 2.0.0;
        include "../../../circuits/group_sig_rsa_verify.circom";
        component main{public [publicKeys, hashed]} = GroupRsaVerifyPkcs1v15(64, 32, 17, 4, 50);