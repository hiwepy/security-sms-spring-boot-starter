package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.userdetails.AuthcUserDetailsService;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationEntryPoint;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationFailureHandler;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProvider;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationSuccessHandler;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityIdentityProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityIdentityProperties.class })
public class SecurityIdentityAutoConfiguration{

	@Autowired
	private SecurityIdentityProperties identityProperties;
	
	@Bean("idcSessionAuthenticationStrategy")
	@ConditionalOnMissingBean(name = "idcSessionAuthenticationStrategy")
	public SessionAuthenticationStrategy idcSessionAuthenticationStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public IdentityCodeAuthenticationEntryPoint idcAuthenticationEntryPoint() {
		return new IdentityCodeAuthenticationEntryPoint(identityProperties.getAuthc().getLoginUrl());
	}
	
	@Bean
	@ConditionalOnMissingBean
	public IdentityCodeAuthenticationFailureHandler idcAuthenticationFailureHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners) {
		return new IdentityCodeAuthenticationFailureHandler(authenticationListeners, identityProperties.getAuthc().getLoginUrl());
	}
	
	@Bean
	public IdentityCodeAuthenticationProvider idcCodeAuthenticationProvider(
			AuthcUserDetailsService authcUserDetailsService, PasswordEncoder passwordEncoder) {
		return new IdentityCodeAuthenticationProvider(authcUserDetailsService, passwordEncoder);
	}

	@Bean
	@ConditionalOnMissingBean
	public IdentityCodeAuthenticationSuccessHandler idcAuthenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners) {
		return new IdentityCodeAuthenticationSuccessHandler(authenticationListeners, identityProperties.getAuthc().getLoginUrl());
	}
	
}
