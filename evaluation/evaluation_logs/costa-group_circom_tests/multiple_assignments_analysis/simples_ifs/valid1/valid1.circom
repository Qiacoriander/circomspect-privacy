


template A(){
   signal input in;
   signal output out;
   
   if (in > 10){
       out <-- in;
   } else{
       out <-- 0;
   }

}

component main = A();
