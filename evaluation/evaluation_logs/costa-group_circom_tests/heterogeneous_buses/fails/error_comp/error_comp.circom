// Simple case, same buses for all the elements in the heterogeneus array of components
// Choose n,m,l to make the array homogeneus or heterogeneus

template A(n){
    signal input in;
    signal output out;
    
    if (n % 2 == 0){
        out <== 1;
    } else{
        out <== 2;
    }

}


template C(){
    component a_aux[3];
    component b_aux[3];
    
    
    signal input in;
    
    signal {tag} aux;
    aux.tag = in;
}


component main = C();


