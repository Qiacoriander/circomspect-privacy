pragma circom 2.1.6;

template Multiply() {
  signal input a;
  signal input b;
  signal input c;
  signal s1;
  signal output out;
  
  s1 <== a * b;
  out <== s1 * c;
}

component main = Multiply();

/*
// Breaking up non-quadratic constraints

 compile R1CS: circom multiply2.circom --r1cs --sym
 print R1CS: snarkjs r1cs print multiply2.r1cs

The R1CS file reflects 2 constraints:
 a * b  = s1
 s1 * c = out

// Generating the witness

```bash
circom multiply2.circom --r1cs --sym --wasm
```

This will regenerate the R1CS and symbol file, but also create a folder called multiply2_js/.
We need to create an input.json file in that folder.
> inside input.json: {"a": "2","b": "3","c": "5"}

 Now we calculate and export the witness with the following command:
> node generate_witness.js multiply2.wasm input.json witness.wtns

  Note: must be cd in the multiply2_js/ folder.

This command creates `witness.wtns`.

> snarkjs wtns export json witness.wtns
This creates `witness.json`

cat witness.json to view contents.

The computed witness has values [1, 30, 2, 3, 5, 6]. 2, 3, and 5 are the inputs, and 6 is the intermediate signal s1 which is the product of 2 and 3.
This follows the expected layout of the R1CS variables in the form [1, out, a, b, c, s1].


*/