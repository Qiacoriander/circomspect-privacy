pragma circom 2.1.2;

function isNegative(x) {
    // half babyjubjub field size
    return x > 10944121435919637611123202872628637544274182200208017171849102093287904247808 ? 1 : 0;
}

function div_ceil(m, n) {
    var ret = 0;

    if (m % n == 0) {
        ret = m \ n;
    } else {
        ret = m \ n + 1;
    }

    return ret;
}

