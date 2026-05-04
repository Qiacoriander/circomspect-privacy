


template A(){
   signal input in;
   signal output out;
   
   if (in > 10){
       out <-- in;
   }
   
   out <--in;

}

component main = A();
