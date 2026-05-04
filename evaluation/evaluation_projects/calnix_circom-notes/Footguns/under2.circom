pragma circom 2.1.6;

template FactorOfFiveFootgun() {

    signal input in;
    signal output out;
    
    // does not create a constraint, since no quadratic *
    out <== in * 5;
}

component main = FactorOfFiveFootgun();


/*

Here we are saying we know x, such that 5x = out, where out is public. 
So if out is 100, we expect x to be 20 right? 
If we look at the R1CS, we see it is in fact empty, no constraints are created!

This is because although <== is a constraint, the constraint it generates is not a quadratic constraint, it is multiplication by a constant.

When we compile the circuit to R1CS, we see it is empty!

```bash
(base) ➜  hello-circom circom footgun.circom --r1cs
template instances: 1
non-linear constraints: 0 ### no constraints ###
linear constraints: 0
public inputs: 0
public outputs: 1
private inputs: 1
private outputs: 0
wires: 2
labels: 3
Written successfully: ./footgun.r1cs
Everything went okay, circom safe
```

The solution is to wire the IsEqual template in to enforce the equality.


*/