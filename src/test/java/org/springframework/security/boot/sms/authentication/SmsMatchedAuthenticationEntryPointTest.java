package org.springframework.security.boot.sms.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.sms.exception.SmsCodeExpiredException;
import org.springframework.security.boot.sms.exception.SmsCodeIncorrectException;
import org.springframework.security.boot.sms.exception.SmsCodeInvalidException;
import org.springframework.security.boot.sms.exception.SmsCodeNotFoundException;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SmsMatchedAuthenticationEntryPoint}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SmsMatchedAuthenticationEntryPoint Tests")
class SmsMatchedAuthenticationEntryPointTest {

    private final SmsMatchedAuthenticationEntryPoint entryPoint = new SmsMatchedAuthenticationEntryPoint();

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        assertThat(entryPoint).isNotNull();
    }

    @Test
    @DisplayName("supports SmsCodeNotFoundException")
    void testSupportsNotFound() {
        assertThat(entryPoint.supports(new SmsCodeNotFoundException("not found"))).isTrue();
    }

    @Test
    @DisplayName("supports SmsCodeExpiredException")
    void testSupportsExpired() {
        assertThat(entryPoint.supports(new SmsCodeExpiredException("expired"))).isTrue();
    }

    @Test
    @DisplayName("supports SmsCodeIncorrectException")
    void testSupportsIncorrect() {
        assertThat(entryPoint.supports(new SmsCodeIncorrectException("incorrect"))).isTrue();
    }

    @Test
    @DisplayName("supports SmsCodeInvalidException")
    void testSupportsInvalid() {
        assertThat(entryPoint.supports(new SmsCodeInvalidException("invalid"))).isTrue();
    }

    @Test
    @DisplayName("does not support generic AuthenticationException")
    void testDoesNotSupportGeneric() {
        assertThat(entryPoint.supports(new AuthenticationException("generic") {})).isFalse();
    }
}
