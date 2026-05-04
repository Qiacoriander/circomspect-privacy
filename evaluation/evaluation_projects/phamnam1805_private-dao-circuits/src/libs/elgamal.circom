pragma circom 2.1.4;
include "../../node_modules/circomlib/circuits/pedersen.circom";
include "../../node_modules/circomlib/circuits/escalarmulany.circom";
include "../../node_modules/circomlib/circuits/gates.circom";

template ElgamalEncrypt() {
    // pubic signal
    signal input publicKey[2];
    signal input u[2];
    signal input c;

    // private signal
    signal input m;
    signal input b;

    var baseX = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var baseY = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    component bBits = Num2Bits(256);
    component escalarMulgB = EscalarMulAny(256);
    bBits.in <== b;
    escalarMulgB.p[0] <== baseX;
    escalarMulgB.p[1] <== baseY;
    for (var i = 0; i < 256; i++) {
        escalarMulgB.e[i] <== bBits.out[i];
    }

    u[0] === escalarMulgB.out[0];
    u[1] === escalarMulgB.out[1];

    component escalarMulhB = EscalarMulAny(256);
    escalarMulhB.p[0] <== publicKey[0];
    escalarMulhB.p[1] <== publicKey[1];
    for (var i = 0; i < 256; i++) {
        escalarMulhB.e[i] <== bBits.out[i];
    }

    component kHasher = Pedersen(1024);
    component uxBits = Num2Bits(256);
    component uyBits = Num2Bits(256);
    component vxBits = Num2Bits(256);
    component vyBits = Num2Bits(256);
    uxBits.in <== u[0];
    uyBits.in <== u[1];
    vxBits.in <== escalarMulhB.out[0];
    vyBits.in <== escalarMulhB.out[1];

    for (var i = 0; i < 256; i++) {
        kHasher.in[i] <== uxBits.out[i];
        kHasher.in[i + 256] <== uyBits.out[i];
        kHasher.in[i + 512] <== vxBits.out[i];
        kHasher.in[i + 768] <== vyBits.out[i];
    }
    var k = kHasher.out[0];

    component kBits = Num2Bits(256);
    component mBits = Num2Bits(256);
    component cBits = Bits2Num(256);
    component xors[256];
    kBits.in <== k;
    mBits.in <== m;

    for (var i = 0; i < 256; i++) {
        xors[i] = XOR();
        xors[i].a <== kBits.out[i];
        xors[i].b <== mBits.out[i];
        cBits.in[i] <== xors[i].out;
    }

    c === cBits.out;
}

template ElgamalDecrypt() {
    // public input
    signal input u[2];
    signal input c;

    // private input
    signal input m;
    signal input privateKey;

    component privateKeyBits = Num2Bits(256);
    component escalarMuluPk = EscalarMulAny(256);
    privateKeyBits.in <== privateKey;
    escalarMuluPk.p[0] <== u[0];
    escalarMuluPk.p[1] <== u[1];
    for (var i = 0; i < 256; i++){
        escalarMuluPk.e[i] <== privateKeyBits.out[i];
    }

    component kHasher = Pedersen(1024);
    component uxBits = Num2Bits(256);
    component uyBits = Num2Bits(256);
    component vxBits = Num2Bits(256);
    component vyBits = Num2Bits(256);
    uxBits.in <== u[0];
    uyBits.in <== u[1];
    vxBits.in <== escalarMuluPk.out[0];
    vyBits.in <== escalarMuluPk.out[1];
    for (var i = 0; i < 256; i++) {
        kHasher.in[i] <== uxBits.out[i];
        kHasher.in[i + 256] <== uyBits.out[i];
        kHasher.in[i + 512] <== vxBits.out[i];
        kHasher.in[i + 768] <== vyBits.out[i];
    }
    var k = kHasher.out[0];

    component kBits = Num2Bits(256);
    component cBits = Num2Bits(256);
    component mBits = Bits2Num(256);
    component xors[256];
    kBits.in <== k;
    cBits.in <== c;

    for (var i = 0; i < 256; i++){
        xors[i] = XOR();
        xors[i].a <== kBits.out[i];
        xors[i].b <== cBits.out[i];
        mBits.in[i] <== xors[i].out;
    }

    m === mBits.out;
}
// component main {public [u, publicKey,c]} = ElgamalEncrypt();
// component main {public [u, c]} = ElgamalDecrypt();
