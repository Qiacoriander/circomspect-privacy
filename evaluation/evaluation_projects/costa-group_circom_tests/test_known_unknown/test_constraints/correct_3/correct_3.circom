


template Prueba(n){

   signal input in;
   signal output out;

   var x = 0;
   var y;
   
   if (in > 5) {
      x = 1;
      y = 3;
   }

   if (n == 1){
      y = 1;
   }
   else{
      y = 0;
   }

   if (y == 1){
      out <== in;
   }
   else{
      out <== 0;
   }
}


component main = Prueba(3);
