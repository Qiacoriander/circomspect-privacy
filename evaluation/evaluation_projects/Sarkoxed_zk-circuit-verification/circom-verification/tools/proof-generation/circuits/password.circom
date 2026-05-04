pragma circom 2.0.0;

include "./circomlib/poseidon.circom";

template isAllowedChar(){
    signal input c;

    var allowed[64] = [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95];
    
    var res = 1;
    signal prod[65];
    prod[0] <-- 1;

    for(var i = 0; i < 64; i++){
        prod[i+1] <== prod[i] * (c - allowed[i]);
    }

    prod[64] === 0;
}

template isAllowed(plen){
    signal input password;

    signal res <-- password >> (plen * 8);
    res === 0;
    
    component check[plen];
    signal chars[plen];
    for(var i = 0; i < plen; i++){
        check[i] = isAllowedChar();
        chars[i] <-- (password >> (8 * i)) & 255;
        check[i].c <== chars[i];
    }   
}

template PasswordProof(plen){
    signal input password;
    signal input salt;
    signal output hash;
    
    component check = isAllowed(plen);
    check.password <== password;

    component phash = Poseidon(2);
    phash.inputs[0] <== salt;
    phash.inputs[1] <== password;
    hash <-- phash.out;
}

component main {public [salt]}= PasswordProof(20);
