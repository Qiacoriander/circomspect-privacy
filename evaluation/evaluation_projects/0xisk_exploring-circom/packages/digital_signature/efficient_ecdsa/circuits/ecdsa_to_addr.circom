pragma circom 2.1.2;

include "./ecdsa_to_pubkey.circom";
include "./to_address/zk-identity/eth.circom";

template ECDSAToAddr() {
    var bits = 256;
    signal input s;
    signal input Tx;
    signal input Ty;
    signal input Ux;
    signal input Uy;

    signal output addr;

    component ecdsaToPubKey =  ECDSAToPubKey();
    ecdsaToPubKey.s <== s;
    ecdsaToPubKey.Tx <== Tx;
    ecdsaToPubKey.Ty <== Ty;
    ecdsaToPubKey.Ux <== Ux;
    ecdsaToPubKey.Uy <== Uy;

    component pubKeyXBits = Num2Bits(256);
    pubKeyXBits.in <== ecdsaToPubKey.pubKeyX;

    component pubKeyYBits = Num2Bits(256);
    pubKeyYBits.in <== ecdsaToPubKey.pubKeyY;

    component pubKeyToAddr = PubkeyToAddress();

    for (var i = 0; i < 256; i++) {
        pubKeyToAddr.pubkeyBits[i] <== pubKeyYBits.out[i];
        pubKeyToAddr.pubkeyBits[i + 256] <== pubKeyXBits.out[i];
    }

    addr <== pubKeyToAddr.address;
}
