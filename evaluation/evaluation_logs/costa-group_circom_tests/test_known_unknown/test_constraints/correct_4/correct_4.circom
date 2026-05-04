

template Prueba(n){

   signal input in;
   signal output out;

   var x = 0;
   var y;
   
   if (n > 5) {
      if (in == 7){
         x = 1;
      }
      y = 3;
   }
   else{
      y = 2;
   }

   if (y == 1){
      out <== in;
   }
   else{
      out <== in + 2;
   }
}


component main = Prueba(3);
