include “eddsa.circom”;
template AuthorizeFabricationOrder() {
    signal public input pkA;
    signal public input pkB;
    signal public input msg;
    signal private input sig;
    signal outA;
    signal outB;
    component verifyA = EdDSAVerifier();
    component verifyB = EdDSAVerifier();
    //verify signature with pkA
    verifyA.pk <== pkA;
    verifyA.msg <== msg;
    verifyA.sig <== sig;
    outA <== verifyA.out;
    //verify signature with pkB
    verifyB.pk <== pkB;
    verifyB.msg <== msg;
    verifyB.sig <== sig;
    outB <== verifyB.out;
    outA + outB === 1;
}
component main = AuthorizeFabricationOrder();