pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template LicenseValid() {
    signal input licenseType;
    signal input requiredLicenseType;
    signal input expirationDate;
    signal input currentDate;
    signal input salt;
    signal output licenseHash;
    signal output isValid;

    // Hash the license data with salt for privacy
    component hasher = Poseidon(3);
    hasher.inputs[0] <== licenseType;
    hasher.inputs[1] <== expirationDate;
    hasher.inputs[2] <== salt;
    licenseHash <== hasher.out;

    // Check type matches
    component typeEq = IsEqual();
    typeEq.in[0] <== licenseType;
    typeEq.in[1] <== requiredLicenseType;

    // Check not expired (expirationDate > currentDate)
    component notExpired = GreaterThan(64);
    notExpired.in[0] <== expirationDate;
    notExpired.in[1] <== currentDate;

    // Both conditions must be true (AND gate)
    isValid <== typeEq.out * notExpired.out;
}

component main {public [requiredLicenseType, currentDate]} = LicenseValid();
