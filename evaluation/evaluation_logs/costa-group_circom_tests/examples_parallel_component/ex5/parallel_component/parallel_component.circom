template Aux(n){
   signal input in[n];
   signal output out[n];
   
   var aux = 0;

   out[0] <== in[0];

   for (aux = 1; aux < n; aux++){
      out[aux] <== out[aux-1] * in[aux];

   
   }

}



template Main(n){
   signal input in;
   signal output out[n];
   
   component c_aux = parallel Aux(n);
   var aux = 0;
   
   for (aux = 0; aux < n; aux++){
      c_aux.in[aux] <== in;
   }
   
   for (aux = 0; aux < n; aux++){
      c_aux.out[aux] ==> out[aux];
   }
}

component main = Main(10);
