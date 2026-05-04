// 多重if嵌套
pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;

    if ( a > 3 ) 
    {
        if (a>3)
        {
            a=1;
            a=2;
        }
    }
    else
    {
        if(a<3)
        {
            b=1;
        }
    }

}

function B(b) {
    if (b>0) 
    {
        if (b>1) 
        {
            if (b>2) 
            {
                if (b>3) 
                {
                    b=4;
                    b=5;
                }
                else
                {
                    b=100;
                }
            }
        }
        else 
        {
            b=1;
        }
    }

    return 1;
}

component main = Multiplier();
