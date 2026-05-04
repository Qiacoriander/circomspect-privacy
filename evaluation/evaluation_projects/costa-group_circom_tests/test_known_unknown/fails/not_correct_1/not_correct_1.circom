template Prueba(n){

   signal input in;

   var x = 0;
   var y = 0;
   var array;
   
   if (in == 1){
      x = 1;
   }
   else{
      x = 2;
   }
   
   signal output out[x];
}


component main = Prueba(3);
