

template B(){
    signal input in1[3];
    signal input in2[3];
    signal output out;

    out <== in1[0] * in2[0];
}



template A(){

   signal input in[3];
   
   signal output out;
   
   component a = B();
   
   var mivar[3] = in;
   
   a.in1 <== mivar;
   a.in2 <== mivar;
   
   out <== a.out;
    
}


component main = A();
