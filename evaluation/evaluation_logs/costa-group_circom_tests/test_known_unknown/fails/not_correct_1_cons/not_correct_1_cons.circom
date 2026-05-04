


template Prueba(){

   signal input in;
   signal output out;

   var x = 0;
   
   if (in > 5) {
      x = 1;
   }

   if (x == 1){
      out <== in;
   }
   else{

   }
}


component main = Prueba();
