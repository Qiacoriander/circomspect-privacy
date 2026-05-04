

template Prueba(n){

   signal input in;
   signal output out;

   var x = 0;
   
   if (n > 5) {
      x = 1;
   }

   if (x == 1){
      out <== in;
   }
   else{
      out <== 0;
   }
}


component main = Prueba(7);
