
template A(){
	signal input in;
	signal output out;
	
	out <== in;
}

template Prueba(n){

   signal input in;
   signal output out;

   var aux = 0;
   var y;
   var x = 5;
   var z = in;
   component a[20];
    for (var i=0; i<n; i++) {
        //a[i] = Ark(t, C, t*i);

            if (i==5) {
                var j = 5;
                
            }

        }

    

 
   
}


component main = Prueba(13);
