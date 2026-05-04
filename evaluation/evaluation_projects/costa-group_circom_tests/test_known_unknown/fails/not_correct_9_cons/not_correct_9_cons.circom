template Prueba(n){

   signal input in;
   signal output out;

   var x = 3;
   var y = 0;
   var aux = 0;
   
   while (y > aux){
      y = x;
      x = in;
      aux = aux + 1;
   }

   if (aux == 1){
      out <== in * in;
   }
   else{
      out <== in * in;
   }
}


component main = Prueba(3);
