package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProvider;
import org.springframework.security.boot.identity.authentication.IdentityCodeMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.identity.authentication.IdentityCodeMatchedAuthenticationFailureHandler;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityIdentityProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityIdentityProperties.class })
public class SecurityIdentityAutoConfiguration{
	
	@Bean
	public IdentityCodeMatchedAuthenticationEntryPoint idcMatchedAuthenticationEntryPoint() {
		return new IdentityCodeMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public IdentityCodeMatchedAuthenticationFailureHandler idcMatchedAuthenticationFailureHandler() {
		return new IdentityCodeMatchedAuthenticationFailureHandler();
	}
	 
	@Bean
	public IdentityCodeAuthenticationProvider idcCodeAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService, PasswordEncoder passwordEncoder) {
		return new IdentityCodeAuthenticationProvider(userDetailsService, passwordEncoder);
	}
	
}
