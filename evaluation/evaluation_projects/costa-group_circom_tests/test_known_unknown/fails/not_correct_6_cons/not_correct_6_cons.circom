

template Prueba(n){

   signal input in;
   signal output out;

   var y;
   
   var x = y + 2;
   
   if (x == 1){
      out <== in * in;
   }
   else{
      out === in * in;
   }
}


component main = Prueba(3);
