pragma circom 2.1.6;

template IsZero() {

  signal input in;
  signal output out;

  signal inv;

  inv <-- in != 0 ? 1/in : 0;

  out <== -in*inv +1;
  in*out === 0;

}

/*

Circom operates in arithmetic modulo p.
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617.


So 1/in returns the multiplicative inverse of in.
    
    in * inv = 1

Explain:   inv <-- in != 0 ? 1/in : 0;

    If input is non-zero, calc the multplicative inverse, and assign it to inv.
    Else, assign inv to be 0.    

If in = 0,

    inv = 0;
    
    (compute, assign, constraint)
    -in*inv +1 = 0*0 + 1 = 1 
        out = 1
        out === 1

    in * out = 0 * 1 = 0  (honouring: in*out === 0)

Therefore, if in = 0, out returns 1.
 

If in = 1,

    inv = 1/1 = 1;

    (compute, assign, constraint)
    -in*inv +1 = -1*1 + 1 = 0
        out = 0
        out === 0

    in * out = 1 * 0 = 0  (honouring: in*out === 0)

Therefore, if in = 1, out returns 0.
*/