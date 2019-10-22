package org.springframework.security.boot;

import java.util.Arrays;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfigurationSource;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties({ SecurityIdentityProperties.class })
public class SecurityIdentityFilterConfiguration {
    
    @Configuration
    @ConditionalOnProperty(prefix = SecurityIdentityProperties.PREFIX, value = "enabled", havingValue = "true")
   	@EnableConfigurationProperties({ SecurityIdentityProperties.class, SecurityBizProperties.class })
    @Order(SecurityProperties.DEFAULT_FILTER_ORDER + 4)
   	static class IdentityWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {
    	
        private final AuthenticationManager authenticationManager;
	    private final ObjectMapper objectMapper;
	    private final RememberMeServices rememberMeServices;
	    private final SecurityBizProperties bizProperties;
    	private final SecurityIdentityAuthcProperties authcProperties;
    	private final IdentityCodeAuthenticationProvider authenticationProvider;
    	private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
 	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
	    
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
   		
   		public IdentityWebSecurityConfigurerAdapter(
   			
   				SecurityBizProperties bizProperties,
   				SecurityIdentityAuthcProperties identityAuthcProperties,

   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<IdentityCodeAuthenticationProvider> authenticationProvider,
   				ObjectProvider<IdentityCodeAuthenticationProcessingFilter> authenticationProcessingFilter,
   				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				ObjectProvider<CorsConfigurationSource> configurationSourceProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				
				@Qualifier("idcAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler
			) {
   			
   			super(bizProperties, csrfTokenRepositoryProvider.getIfAvailable(), configurationSourceProvider.getIfAvailable());
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.bizProperties = bizProperties;
   			this.authcProperties = identityAuthcProperties;
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
   		}
   		
   		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
   			AuthenticationManager parentManager = authenticationManager == null ? super.authenticationManagerBean() : authenticationManager;
			ProviderManager authenticationManager = new ProviderManager( Arrays.asList(authenticationProvider), parentManager);
			// 不擦除认证密码，擦除会导致TokenBasedRememberMeServices因为找不到Credentials再调用UserDetailsService而抛出UsernameNotFoundException
			authenticationManager.setEraseCredentialsAfterAuthentication(false);
			return authenticationManager;
		}
   		
   	    public IdentityCodeAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
   	    	
   			IdentityCodeAuthenticationProcessingFilter authenticationFilter = new IdentityCodeAuthenticationProcessingFilter(
   					objectMapper);
   			
   			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.getMobileParameter()).to(authenticationFilter::setMobileParameter);
			map.from(authcProperties.getCodeParameter()).to(authenticationFilter::setCodeParameter);
			
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
   	        return authenticationFilter;
   	    }
   		
   		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
   	        auth.authenticationProvider(authenticationProvider);
   	        super.configure(auth);
   	    }

   	    @Override
		public void configure(HttpSecurity http) throws Exception {
   	    	
   	    	http.csrf().disable(); // We don't need CSRF for Mobile Code based authentication
   	    	http.antMatcher(authcProperties.getPathPattern())
   	    		.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

   	    	super.configure(http, authcProperties.getCros());
   	    	super.configure(http, authcProperties.getCsrf());
   	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
   	    	
   	    }
   	    
   	    @Override
	    public void configure(WebSecurity web) throws Exception {
	    }

   	}

}
