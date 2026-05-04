template LessThan(n) {

    assert(n <= 252);

    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n+1);

    n2b.in <== in[0] + (1<<n) - in[1];

    //out = 1, if in[0] < in[1]
    out <== 1-n2b.out[n];
}


/*

The code is parameterized by n which is the maximum size of the numbers in bits, though there is an enforced upper limit of 252 bits.

The numbers cannot be larger than 2^n, so adding 1<<n ensures the term in[0] + (1<<n) will always be larger than in[1]. 
The difference is turned into binary, and if the highest bit is still 1, then in[0] is greater than in[1]. 

The final term is 1 minus that bit, so this inverts whether or not the bit is present.
Thus, the component returns 1 if in[0] is less than in[1].

readmore: https://stackoverflow.com/questions/73323540/confused-about-circom-lessthan-implementation
*/


/*

LessThan takes in 2 inputs: in[0], in[1]
If out = 1 -> in[0] < in[1]
If out = 0 -> in[0] > in[1]

Either in[0] or in[1] could be larger; there is no prescribed order.
Both inputs to LessThan are at most n bits.

Example

1) x =2, y =1 

    x = b(10)
    y = b(1)
    therefore, n = 2.

    component n2b = Num2Bits(2+1);  //loop i = 0,1,2

    2 + (1 << 2) - 1 
    = 5
    = b(101)

    out = 1 - n2b.out[n]
           = 1 - n2b.out[2]
           = 1 - 1
           = 0

x > y: component returns 0



assert statement 
- number of bits per input value cannot exceed 252
read more: 
https://blog.trailofbits.com/2023/03/21/circomspect-static-analyzer-circom-more-passes/


*/