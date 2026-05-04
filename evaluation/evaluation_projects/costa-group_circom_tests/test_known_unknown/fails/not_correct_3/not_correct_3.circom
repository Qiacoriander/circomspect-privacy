template Prueba(n){

   signal input in;

   var x = 0;
   var y = 0;
   var array[5];
   
   if (in == 1){
      x = 2;
      array[x] = 7;
   }
   else{
      x = 2;
      array[x] = 5;
   }
   
   signal output out;
   out <== array[x];
}


component main = Prueba(3);
