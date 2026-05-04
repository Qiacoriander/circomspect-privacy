pragma circom 2.0.0;

template ThaiCitizenCheck() {
    // Private input: เลขบัตร 13 หลัก
    signal input idDigits[13];
    
    // Output
    signal output isValid;
    
    // เช็คว่าแต่ละหลักเป็น 0-9
    signal check[13];
    for (var i = 0; i < 13; i++) {
        check[i] <== idDigits[i] * (9 - idDigits[i] + 1);
    }
    
    // Thai ID checksum: หลักที่ 1-12 คูณกับ 13-2 แล้วรวมกัน
    signal sum[12];
    sum[0] <== idDigits[0] * 13;
    for (var i = 1; i < 12; i++) {
        sum[i] <== sum[i-1] + idDigits[i] * (13 - i);
    }
    
    // Checksum calculation
    signal remainder;
    remainder <-- sum[11] % 11;
    
    signal checkDigit;
    checkDigit <-- (11 - remainder) % 10;
    
    // Constraint สำหรับ remainder
    signal quotient;
    quotient <-- sum[11] \ 11;
    sum[11] === quotient * 11 + remainder;
    
    // ตรวจสอบว่า checkDigit ตรงกับหลักสุดท้าย
    signal diff;
    diff <== checkDigit - idDigits[12];
    
    // isValid = 1 ถ้า diff = 0
    isValid <== 1 - diff * diff;
}

component main = ThaiCitizenCheck();