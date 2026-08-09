package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecuritySmsProperties.PREFIX)
@Getter
@Setter
@ToString
/**
 * Configuration properties.
 * <p>Binds to the application property prefix and provides
 * customizable settings.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class SecuritySmsProperties {

	public static final String PREFIX = "spring.security.sms";

	/** Whether Enable SMS Authentication. */
	private boolean enabled = false;

}
