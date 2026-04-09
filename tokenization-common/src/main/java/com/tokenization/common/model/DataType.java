package com.tokenization.common.model;

/**
 * Enumeration of all sensitive data types supported by the tokenization service.
 *
 * <p>WHY: Centralizing data type definitions here ensures consistent handling across all
 * microservices. Each data type carries metadata about its character set (radix) and
 * format constraints used by the FF1 engine and masking layer.</p>
 *
 * <p>COMPLIANCE: These types correspond to data categories regulated under PCI DSS
 * (CREDIT_CARD, ACCOUNT_NUMBER), HIPAA (HEALTH_ID, DATE_OF_BIRTH), and GDPR (EMAIL, PHONE).</p>
 */
public enum DataType {

    /**
     * Primary Account Number (PAN) — 16-digit numeric credit card number.
     * COMPLIANCE: Tokenizing PANs removes them from PCI DSS compliance scope in downstream systems.
     * Format: Numeric, 16 digits. Luhn check on input is optional (not enforced to allow test data).
     */
    CREDIT_CARD(Radix.NUMERIC, 16, MaskPattern.LAST_4),

    /**
     * US Social Security Number — 9 digits, formatted as NNN-NN-NNNN.
     * COMPLIANCE: SSN is classified as PII under US federal law and state regulations.
     */
    SSN(Radix.NUMERIC, 9, MaskPattern.LAST_4),

    /**
     * US/International phone number — digits only (no dashes, spaces).
     * Format: 10–15 digits (E.164 format without leading +).
     */
    PHONE(Radix.NUMERIC, 10, MaskPattern.LAST_4),

    /**
     * Bank account number — numeric, variable length 8–17 digits.
     * COMPLIANCE: Covered under PCI DSS for payment account data protection.
     */
    ACCOUNT_NUMBER(Radix.NUMERIC, 12, MaskPattern.LAST_4),

    /**
     * National health identifier / medical record number.
     * COMPLIANCE: PHI under HIPAA — highest protection tier.
     */
    HEALTH_ID(Radix.ALPHANUMERIC, 10, MaskPattern.FULL_MASK),

    /**
     * Date of birth in YYYYMMDD format (numeric, 8 digits).
     * COMPLIANCE: PHI under HIPAA when combined with other identifiers.
     */
    DATE_OF_BIRTH(Radix.NUMERIC, 8, MaskPattern.FULL_MASK),

    /**
     * Email address local part (before @) — alphanumeric tokenization.
     * WHY: We tokenize only the local part, preserving the domain for operational routing.
     */
    EMAIL(Radix.ALPHANUMERIC, 10, MaskPattern.FULL_MASK),

    /**
     * Custom data type for application-defined sensitive fields.
     * The caller must specify the radix and length in the request.
     */
    CUSTOM(Radix.ALPHANUMERIC, 0, MaskPattern.FULL_MASK);

    /** The character set (radix) this data type uses. Determines FF1 radix parameter. */
    private final Radix radix;

    /** Expected length of the data. Used for domain size validation (radix^length >= 1,000,000). */
    private final int expectedLength;

    /** Default masking pattern applied when a full value cannot be shown. */
    private final MaskPattern defaultMaskPattern;

    DataType(Radix radix, int expectedLength, MaskPattern defaultMaskPattern) {
        this.radix = radix;
        this.expectedLength = expectedLength;
        this.defaultMaskPattern = defaultMaskPattern;
    }

    public Radix getRadix() { return radix; }
    public int getExpectedLength() { return expectedLength; }
    public MaskPattern getDefaultMaskPattern() { return defaultMaskPattern; }

    /**
     * The character set (radix) used by FPE algorithms.
     *
     * <p>WHY: FF1 operates on a defined alphabet. The radix determines which characters
     * are valid in input/output and the mathematical domain size (radix^length >= 1,000,000).</p>
     */
    public enum Radix {
        /** Digits 0–9. Radix = 10. Used for credit cards, SSN, phone numbers. */
        NUMERIC(10, "0123456789"),

        /** Digits 0–9 + lowercase a–z. Radix = 36. Used for IDs, health records, emails. */
        ALPHANUMERIC(36, "0123456789abcdefghijklmnopqrstuvwxyz");

        private final int value;
        private final String alphabet;

        Radix(int value, String alphabet) {
            this.value = value;
            this.alphabet = alphabet;
        }

        public int getValue() { return value; }
        public String getAlphabet() { return alphabet; }
    }

    /**
     * Masking patterns for dynamic data masking (FR-004).
     *
     * <p>WHY: Different roles see different levels of masking. A customer service rep
     * sees LAST_4 (e.g., ****-****-****-1234), while an analyst sees FULL_MASK.</p>
     */
    public enum MaskPattern {
        /** Show only the last 4 characters. e.g., ****-****-****-1234 */
        LAST_4,
        /** Show only the first 4 characters. e.g., 4532-****-****-**** */
        FIRST_4,
        /** Show first 6 and last 4 (industry standard for PAN display). */
        FIRST_6_LAST_4,
        /** Replace all characters with asterisks. */
        FULL_MASK
    }
}
