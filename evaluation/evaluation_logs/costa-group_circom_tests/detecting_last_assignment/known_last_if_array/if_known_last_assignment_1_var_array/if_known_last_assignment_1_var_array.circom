

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
   
   var mivar[3] = in;
   
      if (n > 10){
       a.in1 <-- mivar;
   }
  
   a.in2 <== mivar;
   
      if (n <= 10){
       a.in1 <-- mivar;
   }
   
   out <== a.out;
    
}


component main = A(15);
