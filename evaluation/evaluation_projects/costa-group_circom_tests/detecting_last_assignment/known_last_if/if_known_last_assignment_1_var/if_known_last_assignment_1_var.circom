

template B(){
    signal input in1;
    signal input in2;
    signal output out;

    out <== in1 * in2;
}


template A(n){

   signal input in;
   
   signal output out;
   
   component a = B();
   
   var mivar = in;
   
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
