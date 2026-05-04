

template B(){
    signal input in1;
    signal input in2;
    signal output out;

    out <== in1 * in2;
}


template A(n){

   signal input in1;
   signal input in2;
   
   signal output out;
   
   component a = B();
   
   if (n > 10){
       a.in1 <-- in1;
   }
   a.in2 <== in2;
   if (n <= 10){
       a.in1 <-- in1;
   }
   out <== a.out;
    
}


component main = A(12);
