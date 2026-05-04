


template Prueba(){

   signal input in;
   signal output out;

   var x = 0;
   var y = 3;
   
   if (in > 5) {
      x = 1;
   }

   if (y == 1){
      out <== in;
   }
   else{
      out <== 0;
   }
}


component main = Prueba();
