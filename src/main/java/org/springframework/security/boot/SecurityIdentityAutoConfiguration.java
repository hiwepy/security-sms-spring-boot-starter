package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
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

	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private SecurityIdentityProperties identityProperties;
	
	@Bean("idcAuthenticationSuccessHandler")
	public PostRequestAuthenticationSuccessHandler idcAuthenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationSuccessHandler> successHandlers) {
		
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		
		successHandler.setDefaultTargetUrl(identityProperties.getAuthc().getSuccessUrl());
		successHandler.setStateless(bizProperties.isStateless());
		successHandler.setTargetUrlParameter(identityProperties.getAuthc().getTargetUrlParameter());
		successHandler.setUseReferer(identityProperties.getAuthc().isUseReferer());
		
		return successHandler;
		
	}
	
	@Bean("idcAuthenticationFailureHandler")
	public PostRequestAuthenticationFailureHandler idcAuthenticationFailureHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationFailureHandler> failureHandlers) {
		
		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, failureHandlers);
		
		failureHandler.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(identityProperties.getAuthc().getFailureUrl());
		failureHandler.setStateless(bizProperties.isStateless());
		failureHandler.setUseForward(identityProperties.getAuthc().isUseForward());
		
		return failureHandler;
		
	}
	
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
