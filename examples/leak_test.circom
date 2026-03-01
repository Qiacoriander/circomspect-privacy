pragma circom 2.0.0;

template Hasher() {
    signal input in;
    signal output hash;
    // mock hash using standard components in test
    hash <== in * 12345;
}

template LeakySubcircuit() {
    signal input private_val;
    signal input public_val;
    signal output out;

    // This is a partial leak due to bitwise operation
    out <== (private_val + public_val) & 255;
}

template Main() {
    signal input a;
    signal input b;
    signal input c;

    // A private signal that we want to protect
    signal input secret;

    signal output result;
    signal output safe_hash;

    component sub = LeakySubcircuit();
    sub.private_val <== secret;
    sub.public_val <== a;

    // The result partially leaks the secret
    result <== sub.out + b;

    // A safe usage
    component h = Hasher();
    h.in <== secret;
    safe_hash <== h.hash;
}

component main { public [a, b, c] } = Main();
