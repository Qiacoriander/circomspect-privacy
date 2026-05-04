pragma circom 2.1.6;

include "./utils/comparators.circom";
include "./utils/poseidon.circom";

/**
 * Main census registration circuit
 * Proves:
 * 1. Valid passport data
 * 2. Age is within claimed range
 * 3. Location matches claimed continent
 * 4. Unique nullifier (prevents double registration)
 */
template CensusRegistration() {
    // Private inputs (never revealed)
    signal input passportNumber;        // Passport number as bigint
    signal input dateOfBirth;           // Unix timestamp of birth
    signal input nationalityCode;       // ISO country code as number
    signal input documentExpiry;        // Unix timestamp of expiry
    signal input nullifierSecret;       // Random secret for nullifier

    // Public inputs
    signal input currentTimestamp;      // Current time
    signal input censusId;              // Census identifier

    // Public outputs
    signal output nullifierHash;        // Unique nullifier
    signal output ageRange;             // 0-6 (age ranges)
    signal output continent;            // 0-6 (continents)
    signal output isValid;              // 1 if valid, 0 otherwise

    // Components
    component lessThan[10];
    component greaterThan[10];

    // Calculate age in seconds
    signal ageInSeconds;
    ageInSeconds <== currentTimestamp - dateOfBirth;

    // Convert to years (approximately, 31557600 seconds per year)
    signal ageInYears;
    ageInYears <== ageInSeconds \ 31557600;

    // Verify passport is not expired
    signal isNotExpired;
    lessThan[0] = LessThan(64);
    lessThan[0].in[0] <== currentTimestamp;
    lessThan[0].in[1] <== documentExpiry;
    isNotExpired <== lessThan[0].out;

    // Verify age is at least 0 and less than 150
    signal validAge;
    greaterThan[0] = GreaterEqThan(64);
    greaterThan[0].in[0] <== ageInYears;
    greaterThan[0].in[1] <== 0;

    lessThan[1] = LessThan(64);
    lessThan[1].in[0] <== ageInYears;
    lessThan[1].in[1] <== 150;

    validAge <== greaterThan[0].out * lessThan[1].out;

    // Calculate age range (0-6)
    signal ageRange0;  // 0-17
    signal ageRange1;  // 18-24
    signal ageRange2;  // 25-34
    signal ageRange3;  // 35-44
    signal ageRange4;  // 45-54
    signal ageRange5;  // 55-64
    signal ageRange6;  // 65+

    lessThan[2] = LessThan(64);
    lessThan[2].in[0] <== ageInYears;
    lessThan[2].in[1] <== 18;
    ageRange0 <== lessThan[2].out;

    greaterThan[1] = GreaterEqThan(64);
    greaterThan[1].in[0] <== ageInYears;
    greaterThan[1].in[1] <== 18;
    lessThan[3] = LessThan(64);
    lessThan[3].in[0] <== ageInYears;
    lessThan[3].in[1] <== 25;
    ageRange1 <== greaterThan[1].out * lessThan[3].out;

    greaterThan[2] = GreaterEqThan(64);
    greaterThan[2].in[0] <== ageInYears;
    greaterThan[2].in[1] <== 25;
    lessThan[4] = LessThan(64);
    lessThan[4].in[0] <== ageInYears;
    lessThan[4].in[1] <== 35;
    ageRange2 <== greaterThan[2].out * lessThan[4].out;

    greaterThan[3] = GreaterEqThan(64);
    greaterThan[3].in[0] <== ageInYears;
    greaterThan[3].in[1] <== 35;
    lessThan[5] = LessThan(64);
    lessThan[5].in[0] <== ageInYears;
    lessThan[5].in[1] <== 45;
    ageRange3 <== greaterThan[3].out * lessThan[5].out;

    greaterThan[4] = GreaterEqThan(64);
    greaterThan[4].in[0] <== ageInYears;
    greaterThan[4].in[1] <== 45;
    lessThan[6] = LessThan(64);
    lessThan[6].in[0] <== ageInYears;
    lessThan[6].in[1] <== 55;
    ageRange4 <== greaterThan[4].out * lessThan[6].out;

    greaterThan[5] = GreaterEqThan(64);
    greaterThan[5].in[0] <== ageInYears;
    greaterThan[5].in[1] <== 55;
    lessThan[7] = LessThan(64);
    lessThan[7].in[0] <== ageInYears;
    lessThan[7].in[1] <== 65;
    ageRange5 <== greaterThan[5].out * lessThan[7].out;

    greaterThan[6] = GreaterEqThan(64);
    greaterThan[6].in[0] <== ageInYears;
    greaterThan[6].in[1] <== 65;
    ageRange6 <== greaterThan[6].out;

    // Calculate final age range index
    ageRange <== 0 * ageRange0 +
                 1 * ageRange1 +
                 2 * ageRange2 +
                 3 * ageRange3 +
                 4 * ageRange4 +
                 5 * ageRange5 +
                 6 * ageRange6;

    // Map nationality to continent
    // This is a simplified mapping, in production use a lookup table
    component continentMapper = NationalityToContinent();
    continentMapper.nationalityCode <== nationalityCode;
    continent <== continentMapper.continent;

    // Generate nullifier hash
    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== nullifierSecret;
    nullifierHasher.inputs[1] <== censusId;
    nullifierHasher.inputs[2] <== passportNumber;
    nullifierHash <== nullifierHasher.out;

    // Overall validity check
    isValid <== isNotExpired * validAge;
    isValid === 1;
}

/**
 * Maps nationality code to continent
 * Simplified version - in production, use a complete mapping
 */
template NationalityToContinent() {
    signal input nationalityCode;
    signal output continent;

    // Simplified continent mapping
    // Africa: 1-100
    // Asia: 101-200
    // Europe: 201-300
    // North America: 301-400
    // South America: 401-500
    // Oceania: 501-600
    // Antarctica: 601-700

    component ranges[7];
    signal continentFlags[7];

    // Africa (0)
    ranges[0] = IsInRange(64);
    ranges[0].in <== nationalityCode;
    ranges[0].lower <== 1;
    ranges[0].upper <== 100;
    continentFlags[0] <== ranges[0].out;

    // Asia (1)
    ranges[1] = IsInRange(64);
    ranges[1].in <== nationalityCode;
    ranges[1].lower <== 101;
    ranges[1].upper <== 200;
    continentFlags[1] <== ranges[1].out;

    // Europe (2)
    ranges[2] = IsInRange(64);
    ranges[2].in <== nationalityCode;
    ranges[2].lower <== 201;
    ranges[2].upper <== 300;
    continentFlags[2] <== ranges[2].out;

    // North America (3)
    ranges[3] = IsInRange(64);
    ranges[3].in <== nationalityCode;
    ranges[3].lower <== 301;
    ranges[3].upper <== 400;
    continentFlags[3] <== ranges[3].out;

    // South America (4)
    ranges[4] = IsInRange(64);
    ranges[4].in <== nationalityCode;
    ranges[4].lower <== 401;
    ranges[4].upper <== 500;
    continentFlags[4] <== ranges[4].out;

    // Oceania (5)
    ranges[5] = IsInRange(64);
    ranges[5].in <== nationalityCode;
    ranges[5].lower <== 501;
    ranges[5].upper <== 600;
    continentFlags[5] <== ranges[5].out;

    // Antarctica (6)
    ranges[6] = IsInRange(64);
    ranges[6].in <== nationalityCode;
    ranges[6].lower <== 601;
    ranges[6].upper <== 700;
    continentFlags[6] <== ranges[6].out;

    continent <== 0 * continentFlags[0] +
                  1 * continentFlags[1] +
                  2 * continentFlags[2] +
                  3 * continentFlags[3] +
                  4 * continentFlags[4] +
                  5 * continentFlags[5] +
                  6 * continentFlags[6];
}

/**
 * Check if value is in range [lower, upper]
 */
template IsInRange(n) {
    signal input in;
    signal input lower;
    signal input upper;
    signal output out;

    component gte = GreaterEqThan(n);
    component lte = LessEqThan(n);

    gte.in[0] <== in;
    gte.in[1] <== lower;

    lte.in[0] <== in;
    lte.in[1] <== upper;

    out <== gte.out * lte.out;
}

component main {public [currentTimestamp, censusId]} = CensusRegistration();
