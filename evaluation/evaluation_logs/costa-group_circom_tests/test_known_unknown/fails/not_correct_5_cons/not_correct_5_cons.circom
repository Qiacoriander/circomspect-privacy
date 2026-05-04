


template Prueba(n){

   signal input in;
   signal output out;

   var x = in;
   var y = in;
   var aux = 0;
   
   while (n > aux){
      y = x;
      x = 7;
      aux = aux + 1;
   }

   if (y == 1){
      out <== in * in;
   }
   else{
      out <== in * in;
   }
}


component main = Prueba(3);
