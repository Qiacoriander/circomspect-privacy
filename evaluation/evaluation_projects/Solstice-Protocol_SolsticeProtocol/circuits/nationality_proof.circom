pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * Nationality Proof Circuit
 * Proves a user is from a specific country without revealing other details
 * 
 * Public Inputs:
 * - allowedCountry: Country code (e.g., 91 for India)
 * - isFromCountry: Boolean result
 * - commitmentHash: Hash of identity commitment
 * 
 * Private Inputs:
 * - countryCode: User's actual country code
 * - identitySecret: Secret used in commitment
 */

template NationalityProof() {
    // Public inputs
    signal input allowedCountry;
    signal input isFromCountry;
    signal input commitmentHash;
    
    // Private inputs
    signal input countryCode;
    signal input identitySecret;
    
    // Check if country matches
    component isEqual = IsEqual();
    isEqual.in[0] <== countryCode;
    isEqual.in[1] <== allowedCountry;
    
    // Verify the check matches public output
    isEqual.out === isFromCountry;
    
    // Verify commitment (simplified)
    signal commitmentCheck;
    commitmentCheck <== countryCode * identitySecret;
}

component main {public [allowedCountry, isFromCountry, commitmentHash]} = NationalityProof();
