package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecuritySmsAutoConfiguration}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecuritySmsAutoConfiguration Tests")
class SecuritySmsAutoConfigurationTest {

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        SecuritySmsAutoConfiguration configuration = new SecuritySmsAutoConfiguration();
        assertThat(configuration).isNotNull();
    }
}
