


template A(){
   signal input in;
   signal output out[2];
   
   if (in > 10){
       out[0] <-- in;
   } else{
       if (in > 20){
           out[0] <-- in;
       } else{
           out[0] <-- 0;
       }
   }


}

component main = A();
