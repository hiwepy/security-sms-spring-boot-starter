package org.springframework.security.boot.sms.authentication;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.sms.exception.SmsCodeExpiredException;
import org.springframework.security.boot.sms.exception.SmsCodeIncorrectException;
import org.springframework.security.boot.sms.exception.SmsCodeInvalidException;
import org.springframework.security.boot.sms.exception.SmsCodeNotFoundException;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SmsMatchedAuthenticationFailureHandler}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SmsMatchedAuthenticationFailureHandler Tests")
class SmsMatchedAuthenticationFailureHandlerTest {

    private final SmsMatchedAuthenticationFailureHandler handler = new SmsMatchedAuthenticationFailureHandler();

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("supports SmsCodeNotFoundException")
    void testSupportsNotFound() {
        assertThat(handler.supports(new SmsCodeNotFoundException("not found"))).isTrue();
    }

    @Test
    @DisplayName("supports SmsCodeExpiredException")
    void testSupportsExpired() {
        assertThat(handler.supports(new SmsCodeExpiredException("expired"))).isTrue();
    }

    @Test
    @DisplayName("supports SmsCodeIncorrectException")
    void testSupportsIncorrect() {
        assertThat(handler.supports(new SmsCodeIncorrectException("incorrect"))).isTrue();
    }

    @Test
    @DisplayName("supports SmsCodeInvalidException")
    void testSupportsInvalid() {
        assertThat(handler.supports(new SmsCodeInvalidException("invalid"))).isTrue();
    }

    @Test
    @DisplayName("does not support generic AuthenticationException")
    void testDoesNotSupportGeneric() {
        assertThat(handler.supports(new AuthenticationException("generic") {})).isFalse();
    }

    @Test
    @DisplayName("onAuthenticationFailure writes not-found error response")
    void testOnFailureNotFound() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new SmsCodeNotFoundException("not found"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationFailure writes expired error response")
    void testOnFailureExpired() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new SmsCodeExpiredException("expired"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationFailure writes invalid error response")
    void testOnFailureInvalid() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new SmsCodeInvalidException("invalid"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationFailure writes incorrect error response")
    void testOnFailureIncorrect() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new SmsCodeIncorrectException("incorrect"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationFailure writes generic error response")
    void testOnFailureGeneric() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new AuthenticationException("generic") {});
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isNotEmpty();
    }
}
