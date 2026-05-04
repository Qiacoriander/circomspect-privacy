pragma circom 2.1.2;

include "./secp256k1/mul.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
    ChatGPT Generated

    To test and illustrate the `EfficientECDSA` Circom circuit, we need to understand its purpose and how it works. 
    This circuit is designed to perform a part of the ECDSA (Elliptic Curve Digital Signature Algorithm) verification process,
    specifically the computation involved in verifying a signature against a public key. 
    Let's break down the circuit and then provide mock data for testing.

    ### Circuit Breakdown:
        1. **Inputs**:
        - `s`: Part of the ECDSA signature.
        - `Tx`, `Ty`: Coordinates of point T, which is \( r^{-1} \times R \) in ECDSA, 
        where R is a point on the elliptic curve and r is part of the signature.
        - `Ux`, `Uy`: Coordinates of point U, which is \( -(m \times r^{-1} \times G) \), 
        where m is the message hash, G is the generator point of the elliptic curve, and r is part of the signature.

        2. **Elliptic Curve Multiplication (`sMultT`)**:
        - Multiplies scalar `s` with point T (Tx, Ty).

        3. **Elliptic Curve Addition (`pubKey`)**:
        - Adds the result of the multiplication with point U (Ux, Uy).

        4. **Outputs**:
        - `pubkeyX`, `pubkeyY`: The X and Y coordinates of the resulting point, 
        which should match the public key if the signature is valid.

    ### Mock Data for Testing:
        - **Scalar (`s`)**: A random scalar value, say `1234567890`.
        - **Point T (`Tx`, `Ty`)**: Coordinates of \( r^{-1} \times R \). Let's assume `Tx = 1122334455`, `Ty = 6677889900`.
        - **Point U (`Ux`, `Uy`)**: Coordinates of \( -(m \times r^{-1} \times G) \). Let's assume `Ux = 5566778899`, `Uy = 9988776655`.

    ### Testing the Circuit:
        1. **Input Values**:
        - `s = 1234567890`
        - `Tx = 1122334455`, `Ty = 6677889900`
        - `Ux = 5566778899`, `Uy = 9988776655`

        2. **Run the Circuit**: 
        - Compute `sMultT` and `pubKey`.
        - The outputs `pubkeyX` and `pubkeyY` should be noted.

        3. **Verification**:
        - If this is a valid signature for a message with the given public key, the outputs should match the known public key coordinates.

    ### Illustration for Beginners:
        - **Conceptual Diagram**: Show a flowchart or diagram with inputs feeding into an elliptic curve multiplication block, 
        then into an addition block, leading to the outputs.
        - **Simplified Explanation**: Describe how the circuit mimics part of the ECDSA verification process, 
        using basic elliptic curve operations (multiplication and addition) to derive a point that should match the public key for a valid signature.

    This mock data and the conceptual approach should help test the `EfficientECDSA` circuit and provide a beginner-friendly illustration of its functionality.
*/

template ECDSAToPubKey() {
    var bits = 256;
    signal input s;
    signal input Tx; // T = r^-1 * R
    signal input Ty;
    signal input Ux; // U = -(m * r^-1 * G)
    signal input Uy; 

    signal output pubKeyX;
    signal output pubKeyY;

    // sMultT = S * T
    component sMultT = Secp256k1Mul();
    sMultT.scalar <== s;
    sMultT.xP <== Tx;
    sMultT.yP <== Ty;

    // pubKey = sMultT + U
    component pubKey = Secp256k1AddIncomplete();
    pubKey.xP <== sMultT.outX;
    pubKey.yP <== sMultT.outY;
    pubKey.xQ <== Ux;
    pubKey.yQ <== Uy;

    pubKeyX <== pubKey.outX;
    pubKeyY <== pubKey.outY;
}
