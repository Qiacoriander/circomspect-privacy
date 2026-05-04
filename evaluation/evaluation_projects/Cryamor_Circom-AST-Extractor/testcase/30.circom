pragma circom 2.1.0;

template A(x,y,z) 
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

function B(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function C(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

template D(x,y,z) 
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template E(x,y,z) 
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template F(x,y,z) 
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template G(x,y,z)
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template H(x,y,z)
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template J(x,y,z)
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template K(x,y,z)
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

function L(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function M(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function N(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function O(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}


function P(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function Q(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function R(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}


template S(x,y,z) 
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

function T(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function U(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

template V(x,y,z) 
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template W(x,y,z) 
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template X(x,y,z) 
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template Y(x,y)
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template Z()
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template AA(x,y,z,q)
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

template BB()
{
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal input in5;
    
    signal output out1;
    signal output out2;
    signal output out3;
    signal output out4;
    signal output out5;

    var i=1;
    var o,p=2;
    var a=1,b=2,c=3;
    i=a;
    o=b-c;
    p=1;

    if (i>o)
    {
        out5 <== in5;
        out4 <== in4;
        out3 <== in3;
        out2 <== in1;
        out1 <== in2;
        for (var k=0; j<10; k+=2)
        {
            out5 <== in1+5;
            out4 <== in1+4;
            out3 <== in1+3;
            out2 <== in1+2;
            out1 <== in1+1;
        }
        o-=i;
        if (i>o)
        {
            out5 <== in5;
            out4 <== in4;
            out3 <== in3;
            out2 <== in1;
            out1 <== in2;
            for (var k=0; j<10; k+=2)
            {
                out5 <== in1+5;
                out4 <== in1+4;
                out3 <== in1+3;
                out2 <== in1+2;
                out1 <== in1+1;
            }
            o-=i;
            
        }
    }
    else
    {
        out1 <== in5;
        out2 <== in4;
        out3 <== in3;
        out4 <== in1;
        out5 <== in2;
    }

}

function CC(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function DD(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function EE(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function FF(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}


function HH(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function GG(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

function JJ(a,b,c) 
{
    c=3;
    if (a>2) 
    {
        b=10;
        while(b<3)
        {
            c=3;
            if (a>2) 
            {
                b=10;
                while(b<3)
                {
                    c=3;
                    if (a>2) 
                    {
                        b=10;
                        while(b<3)
                        {
                            b+=2;
                            b-=1;
                        }
                    }
                    else 
                    {
                        a=3;
                    }
                    b+=2;
                    b-=1;
                }
            }
            else 
            {
                a=3;
            }
            b+=2;
            b-=1;
        }
    }
    else 
    {
        a=3;
    }
    return a+b;
}

component main = A(1,2,3);