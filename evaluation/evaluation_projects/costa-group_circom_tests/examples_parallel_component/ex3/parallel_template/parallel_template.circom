template Aux(n){
   signal input in[n];
   signal output out[n];
   
   var aux = 0;
   out[0] <== in[0];
   for (aux = 1; aux < n; aux++){
      out[aux] <== out[aux-1] * in[aux];
   
   }

}


template parallel MultiAux(n){
   signal input in;
   signal output out[n];
   
   component c_aux[n];
   
   for(var i = 0; i < n; i++ ){
   	c_aux[i] =  Aux(n);
   
   
   	var aux = 0;
   	for (aux = 0; aux < n; aux++){
      		c_aux[i].in[aux] <== in;
   	}
        
      	c_aux[i].out[n-1] ==> out[i];
   
   
    }

}


template Main(n){
   signal input in;
   signal output out[n];
   
   component c_aux [n];
   
   for (var i = 1; i < n; i++){
       c_aux[i] = MultiAux(i);
       c_aux[i].in <== in;
   }
   out[0] <== 0;
   for (var i = 1; i < n; i++){
       c_aux[i].out[i-1] ==> out[i];
   }
}

component main = Main(6);
