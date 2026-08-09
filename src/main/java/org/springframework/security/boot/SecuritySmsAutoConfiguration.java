package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.sms.authentication.SmsAuthenticationProvider;
import org.springframework.security.boot.sms.authentication.SmsMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.sms.authentication.SmsMatchedAuthenticationFailureHandler;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecuritySmsProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecuritySmsProperties.class })
/**
 * Auto-configuration for SecuritySms integration.
 * <p>Registers the necessary beans when the feature is enabled.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class SecuritySmsAutoConfiguration{
	
	@Bean
	public SmsMatchedAuthenticationEntryPoint idcMatchedAuthenticationEntryPoint() {
		return new SmsMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public SmsMatchedAuthenticationFailureHandler idcMatchedAuthenticationFailureHandler() {
		return new SmsMatchedAuthenticationFailureHandler();
	}
	 
	@Bean
	public SmsAuthenticationProvider idcCodeAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService, PasswordEncoder passwordEncoder) {
		return new SmsAuthenticationProvider(userDetailsService, passwordEncoder);
	}
	
}
