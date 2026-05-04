
template B(){
   signal output out;
}

template A(){
   signal input in;
   signal output out[2];
   
   if (in > 10){
       out[0] <-- in;
   } else{
       out[0] <-- 0;
   }
   out <-- [2, 2];
	
}

component main = A();
