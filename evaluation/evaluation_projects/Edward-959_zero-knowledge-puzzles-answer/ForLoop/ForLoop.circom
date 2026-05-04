pragma circom 2.1.4;

// Input : 'a',array of length 2 .
// Output : 'c 
// Using a forLoop , add a[0] and a[1] , 4 times in a row .

// template ForLoop() {

//     signal input a[2];
//     signal b[4];
//     signal d;
//     signal output c;

//     d <-- a[0] + a[1];
//     b[0] <-- d;

//     for (var i = 1; i < 4; i++){
//         b[i] <-- b[i - 1] + d;
//     }

//     c <== b[3];

// }  

template ForLoop() {
    signal input a[2];
    signal output c;
    var b = 0;
    var d = a[0] + a[1];

    for (var i = 0; i < 4; i++){
        b += d;
    }
    
    c <== b; 
}

component main = ForLoop();
