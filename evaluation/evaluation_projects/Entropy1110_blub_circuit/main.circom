pragma circom 2.2.2;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template CommandNullifierCircuit() {

    // Private inputs
    signal input sk_user;
    signal input nonce;

    // Public inputs
    signal input deviceId;
    signal input encryptedCmdHash;
    signal input predictedAuthNullifier;
    signal input predictedCmdNullifier;

    // Auth Nullifier = Poseidon(sk_user, deviceId)
    component poseidonAuth = Poseidon(2);
    poseidonAuth.inputs[0] <== sk_user;
    poseidonAuth.inputs[1] <== deviceId;

    // Cmd Nullifier = Poseidon(authNullifier, encryptedCmdHash, nonce)
    component poseidonCmd = Poseidon(3);
    poseidonCmd.inputs[0] <== poseidonAuth.out;
    poseidonCmd.inputs[1] <== encryptedCmdHash;
    poseidonCmd.inputs[2] <== nonce;

    // authNullifier 검증
    component isZeroAuth = IsZero();
    isZeroAuth.in <== poseidonAuth.out - predictedAuthNullifier;

    // cmdNullifier 검증
    component isZeroCmd = IsZero();
    isZeroCmd.in <== poseidonCmd.out - predictedCmdNullifier;

    // Public outputs
    signal output authVerificationOut;
    signal output cmdVerificationOut;

    authVerificationOut <== isZeroAuth.out;
    cmdVerificationOut <== isZeroCmd.out;
}

component main {public [deviceId, encryptedCmdHash, predictedAuthNullifier, predictedCmdNullifier]} = CommandNullifierCircuit();
