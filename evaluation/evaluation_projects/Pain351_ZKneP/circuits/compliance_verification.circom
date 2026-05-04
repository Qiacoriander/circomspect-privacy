pragma circom 2.0.0;
include "circomlib/circuits/comparators.circom";

template ComplianceVerification() {
    // Private inputs
    signal input riskScore;
    signal input transactionCount30d;
    signal input countriesCount;
    signal input accountAge;
    signal input kycLevel;
    
    // Public inputs
    signal input maxRiskScore;
    signal input maxTransactions;
    signal input maxCountries;
    signal input requiredKycLevel;
    
    // Public outputs
    signal output isCompliant;
    signal output riskLevel;
    
    // Individual risk checks
    component riskCheck = LessEqThan(16);
    riskCheck.in[0] <== riskScore;
    riskCheck.in[1] <== maxRiskScore;
    
    component txCheck = LessEqThan(16);
    txCheck.in[0] <== transactionCount30d;
    txCheck.in[1] <== maxTransactions;
    
    component countryCheck = LessEqThan(8);
    countryCheck.in[0] <== countriesCount;
    countryCheck.in[1] <== maxCountries;
    
    component kycCheck = GreaterEqThan(8);
    kycCheck.in[0] <== kycLevel;
    kycCheck.in[1] <== requiredKycLevel;
    
    component ageCheck = GreaterEqThan(16);
    ageCheck.in[0] <== accountAge;
    ageCheck.in[1] <== 30; // Minimum 30 days
    
    // FIXED: Calculate risk level step by step
    signal riskFactors <== (1 - riskCheck.out) + (1 - countryCheck.out);
    
    component lowRisk = LessEqThan(8);
    lowRisk.in[0] <== riskFactors;
    lowRisk.in[1] <== 0;
    
    component medRisk = LessEqThan(8);
    medRisk.in[0] <== riskFactors;
    medRisk.in[1] <== 1;
    
    // Risk level calculation (1=low, 2=medium, 3=high)
    signal lowRiskValue <== lowRisk.out * 1;
    signal medRiskValue <== (1 - lowRisk.out) * medRisk.out * 2;
    signal highRiskValue <== (1 - lowRisk.out) * (1 - medRisk.out) * 3;
    riskLevel <== lowRiskValue + medRiskValue + highRiskValue;
    
    // FIXED: Overall compliance (step by step)
    signal basicCompliance <== riskCheck.out * txCheck.out;
    signal geoCompliance <== countryCheck.out * kycCheck.out;
    signal finalCompliance <== basicCompliance * geoCompliance;
    isCompliant <== finalCompliance * ageCheck.out;
}

component main = ComplianceVerification();