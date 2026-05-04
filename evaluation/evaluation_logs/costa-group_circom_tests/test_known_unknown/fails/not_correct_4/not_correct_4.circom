template Prueba(n){

   signal input in;

   var x = 0;
   var y = 0;
   var array[5];
   
   
   var aux = 0;
   while (aux < 5){
      array[aux] = 7;
      aux = aux + 1;
   }
   
   
   if (in == 1){
      x = 1;
      array[x] = 0;
   }
   else{
      x = 0;
      array[x] = 99;
   }
   
   signal output out;
   out <== array[3];
   
}


component main = Prueba(3);
