pragma circom 2.1.6;

template Multi3 () 
{
    signal input in1;
    signal input in2;
    signal input in3;

    signal output out;
    
    signal out1 <== in1 * in2;
    out <== out1 * in3;
}

component main { public [ in1, in2, in3 ] } = Multi3();

/* INPUT = {
    "in1": "3",
    "in2": "4",
    "in3": "5"
} */
