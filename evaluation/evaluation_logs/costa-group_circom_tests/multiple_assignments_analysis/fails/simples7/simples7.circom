


template A(){
   signal input in;
   signal output out;
   
   while (in > 10){
       out <-- in;
   }
}

component main = A();
