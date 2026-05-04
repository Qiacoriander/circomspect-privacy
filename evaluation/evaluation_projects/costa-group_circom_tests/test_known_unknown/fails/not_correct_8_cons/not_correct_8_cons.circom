template Prueba(n){

   signal input in;
   signal output out;

   var x = 0;
   var y = 0;
   var aux = 0;
   
   while (in > aux){
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
