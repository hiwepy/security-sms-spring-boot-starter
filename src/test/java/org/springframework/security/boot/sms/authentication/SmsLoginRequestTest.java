package org.springframework.security.boot.sms.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SmsLoginRequest}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SmsLoginRequest Tests")
class SmsLoginRequestTest {

    @Test
    @DisplayName("Constructor sets all fields")
    void testConstructor() {
        SmsLoginRequest request = new SmsLoginRequest("13800138000", "123456", "captcha");
        assertThat(request.getMobile()).isEqualTo("13800138000");
        assertThat(request.getCode()).isEqualTo("123456");
        assertThat(request.getCaptcha()).isEqualTo("captcha");
    }

    @Test
    @DisplayName("mobile getter/setter works")
    void testMobile() {
        SmsLoginRequest request = new SmsLoginRequest("old", "code", "captcha");
        request.setMobile("new_mobile");
        assertThat(request.getMobile()).isEqualTo("new_mobile");
    }

    @Test
    @DisplayName("code getter/setter works")
    void testCode() {
        SmsLoginRequest request = new SmsLoginRequest("mobile", "old", "captcha");
        request.setCode("new_code");
        assertThat(request.getCode()).isEqualTo("new_code");
    }

    @Test
    @DisplayName("captcha getter/setter works")
    void testCaptcha() {
        SmsLoginRequest request = new SmsLoginRequest("mobile", "code", "old");
        request.setCaptcha("new_captcha");
        assertThat(request.getCaptcha()).isEqualTo("new_captcha");
    }
}
