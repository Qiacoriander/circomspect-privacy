pragma circom 2.0.0;

template distinct(n, a, b){
    signal input in[n];
    signal prods[n];

    var x = 1;
    prods[0] <== in[0];
    for(var i = 1; i < n; i ++){
        x *= i;
        prods[i] <== prods[i-1] * in[i]; 
    }
    x *= n;
    
    component rgs[n];
    for(var i = 0; i < n; i++){
        rgs[i] = inrange(a, b);
        rgs[i].in <== in[i];
    }
    prods[n-1] === x;
}
    
template bits4(){
    signal input in;
    signal bits[4];
    var bitsum = 0;
    for(var i = 0; i < 4; i++){
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        bitsum = bitsum + 2 ** i * bits[i];
    }
    bitsum === in;
}

template inrange(a, b){
    signal input in;
    component low = bits4();
    component hig = bits4();
    low.in <== in - a;
    hig.in <== in + (15 - b);
}
    

template Sudoku(n, m){
    signal input solution[n][n];
    signal input puzzle[n][n];
    
    for(var i = 0; i < n; i++){
        for(var j = 0; j < n; j++){         
            puzzle[i][j] * (puzzle[i][j] - solution[i][j]) === 0;    
        }
    }
    
    component rows[n];
    component columns[n];
    component boxes[n];

    for(var i = 0; i < n; i++){
        rows[i] = distinct(n, 1, n);
        columns[i] = distinct(n, 1, n);
//        boxes[i] = distinct(n, 1, 9);
        for(var j = 0; j < n; j++){
            rows[i].in[j]    <== solution[i][j];
            columns[i].in[j] <== solution[j][i];
//            var boxx = ((i / m) >> 0) * m + ((j / m) >> 0);
//            var boxy = (i % m) * m + j % m;
//            boxes[i].in[j] <== solution[boxx][boxy];
        }
    }
    for(var k = 0; k < 3; k++){
        for(var z = 0; z < 3; z++){
            boxes[k * 3 + z] = distinct(n, 1, n);
            for(var i = 0; i < 3; i++){
                for(var j = 0; j < 3; j++){
                    boxes[k * 3 + z].in[i * 3 + j] <== solution[k * 3 + j][z * 3 + i];
                }
            }
        }
    }
}
