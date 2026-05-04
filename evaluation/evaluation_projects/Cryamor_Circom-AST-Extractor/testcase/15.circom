// for循环
pragma circom 2.0.0;

template C(x) 
{
    var j = 2;
    for (var j = 0; j < x; j += 1) 
    {
        j += 2;
        x += 1 ;
        for (var k=1; k < j; k-= 1)
        {
            k += j;
            j=k;
        }
    }
}

template D() 
{
    for (var i = 1; i < 10; i += 1) 
    {
        i += 2;
        while (i<10) 
        {
            i -= 1;
            for (var j=0;j<21;j+=3)
            {
                j-=1;
                j+=4;
            }
        }
        i-=3;
        while (i<10) 
        {
            i -= 1;
            for (var j=0;j<21;j+=3)
            {
                j-=1;
                j+=4;
            }
        }
    }
    for (var j=0;j<21;j+=3)
    {
        j-=1;
        j+=4;
    }
}

component main = C(1);
