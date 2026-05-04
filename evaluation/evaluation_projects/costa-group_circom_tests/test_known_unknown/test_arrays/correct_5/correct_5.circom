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
   
   
   if (n == 1){
      x = 1;
      array[x] = 0;
   }
   else{
      x = 0;
      array[x] = 99;
   }
   aux = 0;
   while (aux < 5){
      log(array[aux]);
      aux = aux + 1;
   }
   
}


component main = Prueba(3);
