package com.tokenization.engine.service;

import com.tokenization.common.dto.MaskRequest;
import com.tokenization.common.dto.MaskResponse;
import com.tokenization.common.model.DataType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for the MaskingService.
 */
class MaskingServiceTest {

    private MaskingService maskingService;

    @BeforeEach
    void setUp() {
        maskingService = new MaskingService();
    }

    @Test
    @DisplayName("LAST_4 mask on credit card token shows formatted last 4 digits")
    void mask_last4_creditCard_formattedCorrectly() {
        MaskResponse response = maskingService.mask(
            new MaskRequest("4716234512839012", DataType.MaskPattern.LAST_4, DataType.CREDIT_CARD));
        // WHY: Credit card display should show groups of 4 separated by dashes
        assertThat(response.masked()).isEqualTo("****-****-****-9012");
    }

    @Test
    @DisplayName("FULL_MASK replaces all characters with asterisks")
    void mask_fullMask_allAsterisks() {
        MaskResponse response = maskingService.mask(
            new MaskRequest("123456789", DataType.MaskPattern.FULL_MASK, DataType.SSN));
        assertThat(response.masked()).isEqualTo("*********");
    }

    @Test
    @DisplayName("FIRST_6_LAST_4 mask on credit card shows BIN and last 4")
    void mask_first6Last4_creditCard() {
        MaskResponse response = maskingService.mask(
            new MaskRequest("4716234512839012", DataType.MaskPattern.FIRST_6_LAST_4, DataType.CREDIT_CARD));
        assertThat(response.masked()).isEqualTo("4716-23**-****-9012");
    }

    @Test
    @DisplayName("SSN LAST_4 produces formatted NNN-NN-XXXX output")
    void mask_last4_ssn_formatted() {
        MaskResponse response = maskingService.mask(
            new MaskRequest("123456789", DataType.MaskPattern.LAST_4, DataType.SSN));
        assertThat(response.masked()).isEqualTo("***-**-6789");
    }

    @Test
    @DisplayName("maskPatternApplied in response matches requested pattern")
    void mask_responseContainsAppliedPattern() {
        MaskResponse response = maskingService.mask(
            new MaskRequest("4716234512839012", DataType.MaskPattern.LAST_4, DataType.CREDIT_CARD));
        assertThat(response.maskPatternApplied()).isEqualTo("LAST_4");
    }
}
