pragma circom 2.1.1;

include "./utils/utils.circom";

template MiMC3D(H, W, D) {
    signal input dummy;
    signal input arr[H][W][D]; 
    signal output h;

    h <== MimcHashMatrix3D(H, W, D)(arr);
    log("MIMC HASH: ", h);
}

component main { public [ dummy ] } = MiMC3D(32, 32, 32);
