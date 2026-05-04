pragma circom 2.1.6;

template Powers {
    signal input a;
    signal output powers[6];
   
    powers[0] <== a;
    powers[1] <== a * a;
    powers[2] <-- a ** 3;
    powers[3] <-- a ** 4;
    powers[4] <-- a ** 5;
    powers[5] <-- a ** 6;
    
}


component main = Powers();




/*
When running into the issue of quadratic constraints, it can be tempting to use the <-- operator to silence the compiler. 
The following code compiles, and seems to accomplish the same as our earlier powers example.

However, when we create the R1CS, we only have on constraint!
With only one constraint, the prover only has to set the first element in the array correctly, but can put whatever value they like for the other 5! 
You cannot trust proofs that come out of a circuit like this!

Compilation:

```bash
(base) ➜  hello-circom circom bad-powers.circom --r1cs
template instances: 1
non-linear constraints: 1 ### only one constraint ###
linear constraints: 0
public inputs: 0
public outputs: 6
private inputs: 1
private outputs: 0
wires: 7
labels: 8
Written successfully: ./powers.r1cs
Everything went okay, circom safe
```
*/