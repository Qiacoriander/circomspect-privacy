


template A(){
   signal input in;
   signal output out[3];
   
   if (in > 10){
       out[0] <-- in;
   } else{
       out[1] <-- 0;
       out[0] <-- in;
   }
   out[2] <-- 2;

}

component main = A();
