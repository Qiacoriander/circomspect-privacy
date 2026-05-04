template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0; 
    // this serves as an accumulator to "recompute" in bit-by-bit
    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0; // force out[i] to be 1 or 0
        lc1 += out[i] * e2; //add to the accumulator if the bit is 1 
        e2 = e2+e2; // takes on values 1,2,4,8,...
    }

    lc1 === in;
}



/*
targetting the bits from teh RHS
- move from right to left

each bit is assessed to be 1 or 0, via & 1:
- 101
& 001
-----
  001  -> 1

if RHS bit is 1, return 1. else return 0.

bit value is stored in out[n].
- out[0]: stores the most RHS bit 
- out[n]: left-most bit

lc1
- serves to accumulate the integer values, to finally return the 'in' value at the end.
- += integer value
- prev. value + (1/0 * bitValue),
- bit value = 1,2,4,8....

e2
- tracks the current bit value
- incements through the binary bases: 1, 2, 4....


EXAMPLE:

5 = b(101)
-------------
in =5 
lc1 = 0
e2 =1 
-------------

# Loop 0:

out[0] = (5 >> 0) & 1
       = b(101)
         & 001
        --------
           001   -> 1 

    out[0] = 1

lc1 += 1 * e2 
     = 0 + (1 * 1)
     = 1

e2 = e2 + e2 = 1 + 1 = 2 

# Loop 1:

out[1] = (5 >> 1) & 1
       = b(010)
         & 001
        --------
           000   -> 0

    out[1] = 0

lc1 += 0 * e2 
     = 0 + (0 * 2)
     = 1

e2 = e2 + e2 = 2 + 2 = 4

# Loop 2:

out[2] = (5 >> 2) & 1
       = b(001)
         & 001
        --------
           001   -> 1

    out[2] = 1

lc1 += 1 * e2 
     = 1 + (4 * 4)
     = 5

e2 = e2 + e2 = 4 + 4 = 8

# Verfication
     lc1 === in; (5 === 5)

*/