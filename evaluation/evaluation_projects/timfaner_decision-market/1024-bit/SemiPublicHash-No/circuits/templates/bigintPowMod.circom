pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/bitify.circom";
include "./bigint.circom";



template bigInt2BitsEndian(n, k, l){
    // var l = n * k;
    assert(l <= n*k);
    signal input in[k];
    signal output out[l];
    signal outLittleEndian[n * k];

    component Register2Bits[k]; 
    for (var i=0; i<k; i++){
        Register2Bits[i]= Num2Bits(n);
        Register2Bits[i].in <== in[i];
        for (var j=0; j<n; j++){
            outLittleEndian[n*i + j] <== Register2Bits[i].out[j];
        }
    }
    for (var i=0; i< l; i++){
        out[i] <== outLittleEndian[l-i-1]; 
    }
}


// template bigInt2BitsLittleEndian(n, k, l){
//     // var l = n * k;
//     assert(l <= n*k);
//     signal input in[k];
//     signal output out[l];
//     signal outLittleEndian[n * k];

//     component Register2Bits[k]; 
//     for (var i=0; i<k; i++){
//         Register2Bits[i]= Num2Bits(n);
//         Register2Bits[i].in <== in[i];
//         for (var j=0; j<n; j++){
//             outLittleEndian[n*i + j] <== Register2Bits[i].out[j];
//         }
//     }
//     for (var i=0; i< l; i++){
//         out[i] <== outLittleEndian[i]; 
//     }
// }




template powMod(n, k, ke, l){
    assert(n<=126);
    signal input base[k];
    signal input exp[ke];
    signal input modulus[k];
    signal output out[k];

    // var l = n * k;

    component exp2Bits = bigInt2BitsEndian(n, ke, l);
    for (var i=0; i<ke; i++){
        exp2Bits.in[i] <== exp[i];
    }
    
    component sqauring[l-1];
    component multiplying[l-1];
    // signal outSqauring[l-1][k];
    signal outStep[l][k];
    
    outStep[0][0] <==  1 +  exp2Bits.out[0] * (base[0] - 1);
    for (var j=1;j<k;j++){
        outStep[0][j] <== exp2Bits.out[0] * base[j];
    }
    
    for(var i=0; i<l-1; i++){
        sqauring[i] = BigMultModP(n, k);
        for(var j=0;j<k;j++){
            sqauring[i].a[j] <== outStep[i][j];
            sqauring[i].b[j] <== outStep[i][j];
            sqauring[i].p[j] <== modulus[j];
        }

        multiplying[i] = BigMultModP(n, k);
        for(var j=0;j<k;j++){
            multiplying[i].a[j] <== sqauring[i].out[j];
            multiplying[i].b[j] <== base[j];
            multiplying[i].p[j] <== modulus[j];
        }
        for(var j=0;j<k;j++){
        outStep[i+1][j] <== sqauring[i].out[j] + exp2Bits.out[i+1] * (multiplying[i].out[j] - sqauring[i].out[j]);
        }
    }

    for(var j=0;j<k;j++){
        out[j] <== outStep[l-1][j];
        }
    
}



// template powMod2(n, k, l){
//     assert(n<=126);
//     // signal input base[k];
//     signal input exp[k];
//     signal input modulus[k];
//     signal input sqauringSteps[l][k];
//     signal output out[k];
    
//     // base = sqauringSteps[0]
//     // signal base[k];
//     // for (var i=0; i<k; i++){
//     //     base[i] <== sqauringSteps[0][i];
//     // }
//     // var l = n * k;

//     component exp2Bits = bigInt2BitsLittleEndian(n, k, l);
//     for (var i=0; i<k; i++){
//         exp2Bits.in[i] <== exp[i];
//     }
    
//     // component sqauring[l-1];
//     component multiplying[l-1];
//     // signal outSqauring[l-1][k];
//     signal outFirstStep[k];
    

//     // First step
//     outFirstStep[0] <==  1 +  exp2Bits.out[0] * (sqauringSteps[0][0] - 1);
//     for (var j=1;j<k;j++){
//         outFirstStep[j] <== exp2Bits.out[0] * sqauringSteps[0][j];
//     }
    
//     // Second step
//     multiplying[0] = BigMultModP(n, k);
//     multiplying[0].a[0] <== outFirstStep[0];
//     multiplying[0].b[0] <== 1 + exp2Bits.out[1] *(sqauringSteps[1][0] - 1);
//     multiplying[0].p[0] <== modulus[0];

//     for(var j=1;j<k;j++){
//         multiplying[0].a[j] <== outFirstStep[j];
//         multiplying[0].b[j] <== exp2Bits.out[1] * sqauringSteps[1][j];
//         multiplying[0].p[j] <== modulus[j];
//     }

//     // Other steps
//     for(var i=2; i<l; i++){
//         multiplying[i-1] = BigMultModP(n, k);
//         multiplying[i-1].a[0] <== multiplying[i-2].out[0];
//         multiplying[i-1].b[0] <== 1 + exp2Bits.out[i] *(sqauringSteps[i][0] - 1);
//         multiplying[i-1].p[0] <== modulus[0];

//         for(var j=1;j<k;j++){
//             multiplying[i-1].a[j] <== multiplying[i-2].out[j];
//             multiplying[i-1].b[j] <== exp2Bits.out[i] * sqauringSteps[i][j];
//             multiplying[i-1].p[j] <== modulus[j];
//         }
//     }

//     for(var j=0;j<k;j++){
//         out[j] <== multiplying[l-2].out[j];
//         }
    
// }



// component main {public [sqauringSteps, modulus]} = powMod2(114, 9, 1024);