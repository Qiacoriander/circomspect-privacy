

template B(){
    signal input in1[3];
    signal input in2[3];
    signal output out;

    out <== in1[0] * in2[0];
}

template A(){

   signal input in1[3];
   signal input in2[3];
   
   signal output out;
   
   component a = B();
   
   a.in1 <== in1;
   a.in2 <== in2;
   
   out <== a.out;
    
}


component main = A();
