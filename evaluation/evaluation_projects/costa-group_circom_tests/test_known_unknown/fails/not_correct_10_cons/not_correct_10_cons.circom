template Prueba(n){

   signal input in;
   signal output out;


   var y = 0;

   
   while (y < 200000){
      if (y == 6){
      //out <-- in;
      }
      y = y + 1;
   }

}


component main = Prueba(3);
