pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/comparators.circom";
include "./node_modules/circomlib/circuits/eddsamimcsponge.circom";

template SignatureProve() {
    
    //verify signature
    signal input enabled;
    signal input debtor_Ax;
    signal input debtor_Ay;
    signal input debtor_S;
    signal input debtor_R8x;
    signal input debtor_R8y;
    signal input transaction_amount;

    component verifySignature_debtor = EdDSAMiMCSpongeVerifier();
    verifySignature_debtor.enabled <== 1;
    verifySignature_debtor.Ax <== debtor_Ax;
    verifySignature_debtor.Ay <== debtor_Ay;
    verifySignature_debtor.R8x <== debtor_R8x;
    verifySignature_debtor.R8y <== debtor_R8y;
    verifySignature_debtor.S <== debtor_S;
    verifySignature_debtor.M <== transaction_amount;

    // verify sufficient money
    signal input total_asset;
    component checkMoneySupplies = LessEqThan(64);
    checkMoneySupplies.in[0] <== transaction_amount;
    checkMoneySupplies.in[1] <== total_asset;
    checkMoneySupplies.out === 1;

}

component main{public [debtor_Ax, debtor_Ay]} = SignatureProve();