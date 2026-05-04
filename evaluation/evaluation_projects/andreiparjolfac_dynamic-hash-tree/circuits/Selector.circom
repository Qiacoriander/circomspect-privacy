pragma circom 2.1.6;


template Selector(){
    signal input switcher;
    signal input in[2];
    signal int[4];
    signal output out[2];
    0 === (switcher)*(1-switcher);
    int[0] <== in[0]*(1-switcher);
    int[1] <== in[1]*switcher;
    out[0] <== int[0] + int[1];

    int[2] <== in[1]*(1-switcher);
    int[3] <== in[0]*switcher;
    out[1] <== int[2] + int[3];

}
