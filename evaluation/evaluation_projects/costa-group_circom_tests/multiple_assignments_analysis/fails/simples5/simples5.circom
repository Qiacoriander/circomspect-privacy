


template A(){
   signal input in;
   signal output out;
   
   if (in > 10){
       out <-- in;
   }
   
   if (in < 20){
       out <-- in;
   }

}

component main = A();
