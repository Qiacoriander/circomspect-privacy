template Prueba(n){

   signal input in;

   var x = 0;
   var y = 0;
   
   if (n == 1){
      x = 1;
      var array[x];
      array[0] = 7; 
   }
   else{
      x = 2;
      var array[x];
      array[1] = 7;
   }
   
}


component main = Prueba(3);
