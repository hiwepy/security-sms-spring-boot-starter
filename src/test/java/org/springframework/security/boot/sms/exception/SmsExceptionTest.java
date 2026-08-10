package org.springframework.security.boot.sms.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SMS exception classes.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SMS Exception Tests")
class SmsExceptionTest {

    @Test
    @DisplayName("SmsCodeExpiredException single-arg constructor")
    void testExpiredExceptionMessage() {
        SmsCodeExpiredException ex = new SmsCodeExpiredException("expired");
        assertThat(ex.getMessage()).isEqualTo("expired");
    }

    @Test
    @DisplayName("SmsCodeExpiredException two-arg constructor")
    void testExpiredExceptionMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        SmsCodeExpiredException ex = new SmsCodeExpiredException("expired", cause);
        assertThat(ex.getMessage()).isEqualTo("expired");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("SmsCodeIncorrectException single-arg constructor")
    void testIncorrectExceptionMessage() {
        SmsCodeIncorrectException ex = new SmsCodeIncorrectException("incorrect");
        assertThat(ex.getMessage()).isEqualTo("incorrect");
    }

    @Test
    @DisplayName("SmsCodeIncorrectException two-arg constructor")
    void testIncorrectExceptionMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        SmsCodeIncorrectException ex = new SmsCodeIncorrectException("incorrect", cause);
        assertThat(ex.getMessage()).isEqualTo("incorrect");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("SmsCodeInvalidException single-arg constructor")
    void testInvalidExceptionMessage() {
        SmsCodeInvalidException ex = new SmsCodeInvalidException("invalid");
        assertThat(ex.getMessage()).isEqualTo("invalid");
    }

    @Test
    @DisplayName("SmsCodeInvalidException two-arg constructor")
    void testInvalidExceptionMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        SmsCodeInvalidException ex = new SmsCodeInvalidException("invalid", cause);
        assertThat(ex.getMessage()).isEqualTo("invalid");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("SmsCodeNotFoundException single-arg constructor")
    void testNotFoundExceptionMessage() {
        SmsCodeNotFoundException ex = new SmsCodeNotFoundException("not found");
        assertThat(ex.getMessage()).isEqualTo("not found");
    }

    @Test
    @DisplayName("SmsCodeNotFoundException two-arg constructor")
    void testNotFoundExceptionMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        SmsCodeNotFoundException ex = new SmsCodeNotFoundException("not found", cause);
        assertThat(ex.getMessage()).isEqualTo("not found");
        assertThat(ex.getCause()).isEqualTo(cause);
    }
}
