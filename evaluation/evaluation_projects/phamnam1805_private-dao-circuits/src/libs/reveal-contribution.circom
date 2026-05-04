pragma circom 2.1.4;
include "./elgamal.circom";

template AddMod(n) {
    signal input elements[n];
    signal output out;

    var modulo = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    var sum = 0;
    for (var i = 0; i < n; i++) {
        sum = (sum + elements[i]) % modulo;
    }
    out <-- sum;
}

template verifyF(t){

    // public signal
    signal input senderIndex;
    signal input C[t][2];

    // private signal
    signal input f;
    signal input privateKey;

    var baseX = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var baseY = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    var x = 1;
    component iBits[t];
    component escalarMulRights[t];
    iBits[0] = Num2Bits(256);
    escalarMulRights[0] = EscalarMulAny(256);
    iBits[0].in <-- x;
    escalarMulRights[0].p[0] <== C[0][0];
    escalarMulRights[0].p[1] <== C[0][1];
    for (var i = 0; i < 256; i++){
        escalarMulRights[0].e[i] <== iBits[0].out[i];
    }
    for (var i = 1 ; i < t; i++) {
        x = x * senderIndex;
        iBits[i] = Num2Bits(256);
        escalarMulRights[i] = EscalarMulAny(256);
        iBits[i].in <-- x;
        escalarMulRights[i].p[0] <== C[i][0];
        escalarMulRights[i].p[1] <== C[i][1];
        for( var j = 0; j < 256; j++){
            escalarMulRights[i].e[j] <== iBits[i].out[j];
        }
    }

    component adders[t];
    adders[0] = BabyAdd();
    adders[0].x1 <== 0;
    adders[0].y1 <== 1;
    adders[0].x2 <== escalarMulRights[0].out[0];
    adders[0].y2 <== escalarMulRights[0].out[1];

     for(var i = 1; i < t; i++){
        adders[i] = BabyAdd();
        adders[i].x1 <== adders[i-1].xout;
        adders[i].y1 <== adders[i-1].yout;
        adders[i].x2 <== escalarMulRights[i].out[0];
        adders[i].y2 <== escalarMulRights[i].out[1];
    }

    component fBits = Num2Bits(256);
    component escalarMulLeft = EscalarMulAny(256);
    fBits.in <== f;
    escalarMulLeft.p[0] <== baseX;
    escalarMulLeft.p[1] <== baseY;
    for (var i = 0; i < 256; i++) {
        escalarMulLeft.e[i] <== fBits.out[i];
    }
    adders[t-1].xout === escalarMulLeft.out[0];
    adders[t-1].yout === escalarMulLeft.out[1];

    component privateKeyBits = Num2Bits(256);
    component escalarMulPrivateKey = EscalarMulAny(256);
    privateKeyBits.in <== privateKey;
    escalarMulPrivateKey.p[0] <== baseX;
    escalarMulPrivateKey.p[1] <== baseY;
    for (var i = 0; i < 256; i++) {
        escalarMulPrivateKey.e[i] <== privateKeyBits.out[i];
    }

    C[0][0] === escalarMulPrivateKey.out[0];
    C[0][1] === escalarMulPrivateKey.out[1];
}

template RevealContribute(n, t, d) {
    // public signal
    signal input senderIndex;
    signal input C[t][2];
    signal input u[n-1][2];
    signal input c[n-1];
    signal input R[d][2];
    signal input D[d][2];

    // private signal
    signal input decryptedF[n-1];
    signal input f;
    signal input privateKey;
    signal input partialSecret;

    component fVerifier = verifyF(t);
    fVerifier.senderIndex <== senderIndex;
    fVerifier.f <== f;
    fVerifier.privateKey <== privateKey;
    for(var i = 0; i < t; i++){
        fVerifier.C[i][0] <== C[i][0];
        fVerifier.C[i][1] <== C[i][1];
    }

    component fDecryption[n-1];
    component fSum = AddMod(n);
    
    for (var i = 0; i < n-1; i++) {
        fDecryption[i] = ElgamalDecrypt();

        fDecryption[i].u[0] <== u[i][0];
        fDecryption[i].u[1] <== u[i][1];
        fDecryption[i].c <== c[i];
        fDecryption[i].m <== decryptedF[i];
        fDecryption[i].privateKey <== privateKey;

        fSum.elements[i] <== decryptedF[i];
    }
    fSum.elements[n-1] <== f;
    
    partialSecret === fSum.out;

    component skBits = Num2Bits(256);
    component escalarmulSecret[d];
    skBits.in <== partialSecret;
    for (var i = 0; i < d; i++) {
        escalarmulSecret[i] = EscalarMulAny(256);
        
        escalarmulSecret[i].p[0] <== R[i][0];
        escalarmulSecret[i].p[1] <== R[i][1];
        for (var j = 0; j < 256; j++) {
            escalarmulSecret[i].e[j] <== skBits.out[j];
        }

        D[i][0] === escalarmulSecret[i].out[0];
        D[i][1] === escalarmulSecret[i].out[1];
    }
}