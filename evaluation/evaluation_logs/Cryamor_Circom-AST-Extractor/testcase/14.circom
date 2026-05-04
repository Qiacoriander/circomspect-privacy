// 多重while嵌套
pragma circom 2.0.0;

template C(x) 
{
    while ( x != 3) 
    {
        while ( x != 4) 
        {
            x = 4;
            while ( x != 5) 
            {
                x = 5;
                while ( x == 6) 
                {
                    x = 7;
                    x=8;
                }
                x=6;
            }
        }
    }
    while ( x != 3) 
    {
        while ( x != 4) 
        {
            x = 4;
            while ( x != 5) 
            {
                x = 5;
                while ( x == 6) 
                {
                    x = 7;
                    x=8;
                }
                x=6;
            }
        }
    }
}

template D() {
    var i = 1;
    while ( i != 3) {
        i = 3;
    }
}

template E() {
    var a=1, b=20;
    while (a<b) {
        a+=2;
        b-=1;
    }
}

component main = C(1);
