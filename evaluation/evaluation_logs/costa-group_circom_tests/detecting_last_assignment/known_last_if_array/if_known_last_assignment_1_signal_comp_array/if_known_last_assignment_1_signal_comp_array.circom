
template C(){
    signal input in[3];
    signal output out[3];
    
    out <== in;
}


template B(){
    signal input in1[3];
    signal input in2[3];
    signal output out;

    out <== in1[2] * in2[1];
}

template A(n){

   signal input in[3];
   
   signal output out;
   
   component a = B();
   component a1 = C();
   
   a1.in <== in;
      if (n > 10){
       a.in1 <-- a1.out;
   }
   
   a.in2 <== a1.out;
   
      if (n <= 10){
       a.in1 <-- a1.out;
   }
   
   out <== a.out;
    
}


component main = A(2);
