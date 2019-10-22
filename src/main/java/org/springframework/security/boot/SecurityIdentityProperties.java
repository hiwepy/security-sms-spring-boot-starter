package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityIdentityProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityIdentityProperties {

	public static final String PREFIX = "spring.security.identity";

	/** Whether Enable JWT Authentication. */
	private boolean enabled = false;

}
