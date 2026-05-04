pragma circom 2.0.0;

template Internal() {
   signal input in[2];
   signal output out;
   out <== in[0]*in[1];
}

template Main1() {
   signal input in[2];
   signal output out;
   component c = Internal ();
   c.in[0] <== in[0];
   c.in[1] <== in[1]+2*in[0]+1;
   c.out ==> out;
}


 component main  = Main1();