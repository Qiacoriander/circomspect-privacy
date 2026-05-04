template Prueba(n){

   signal input in;
   signal output out;

   var x = 0;
   var y = 0;
   var aux = 0;
   
   while (n > aux){
      y = x;
      x = in;
      aux = aux + 1;
   }

   if (y == 1){
      log(1);
   }
   else{
      log(3);
   }
   
   if(aux == 3){
      out <== in * in;
   } 
}


component main = Prueba(13);
