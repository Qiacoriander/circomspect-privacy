template Prueba(n){

   signal input in;
   signal output out;

   var x = 0;
   var y;
   
   if (in > 9) {
      y = 3;
   }

   if (y == 1){
      out <== in * in;
   }
   else{
      out === in * in;
   }
}


component main = Prueba(3);
