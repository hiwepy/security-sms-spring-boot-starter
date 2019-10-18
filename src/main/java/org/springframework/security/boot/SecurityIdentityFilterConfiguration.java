package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties({ SecurityIdentityProperties.class })
public class SecurityIdentityFilterConfiguration {
    
    @Configuration
    @ConditionalOnProperty(prefix = SecurityIdentityProperties.PREFIX, value = "enabled", havingValue = "true")
   	@EnableConfigurationProperties({ SecurityIdentityProperties.class, SecurityBizProperties.class })
    @Order(104)
   	static class IdentityWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    	
        private final AuthenticationManager authenticationManager;
	    private final ObjectMapper objectMapper;
	    private final RememberMeServices rememberMeServices;
	    private final SecurityBizProperties bizProperties;
    	private final SecurityIdentityProperties identityProperties;
    	private final IdentityCodeAuthenticationProvider authenticationProvider;
    	private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
 	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
	    
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
   		
   		public IdentityWebSecurityConfigurerAdapter(
   			
   				SecurityBizProperties bizProperties,
   				SecurityIdentityProperties identityProperties,

   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<IdentityCodeAuthenticationProvider> authenticationProvider,
   				ObjectProvider<IdentityCodeAuthenticationProcessingFilter> authenticationProcessingFilter,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				
				@Qualifier("idcAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler
			) {
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.bizProperties = bizProperties;
   			this.identityProperties = identityProperties;
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
   		}
   		
   		@Bean
   	    public IdentityCodeAuthenticationProcessingFilter authenticationProcessingFilter() {
   	    	
   			IdentityCodeAuthenticationProcessingFilter authenticationFilter = new IdentityCodeAuthenticationProcessingFilter(
   					objectMapper);
   			
   			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(identityProperties.getAuthc().getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(identityProperties.getAuthc().getMobileParameter()).to(authenticationFilter::setMobileParameter);
			map.from(identityProperties.getAuthc().getCodeParameter()).to(authenticationFilter::setCodeParameter);
			
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(identityProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
   	        return authenticationFilter;
   	    }
   		
   		@Override
   	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
   	        auth.authenticationProvider(authenticationProvider);
   	    }

   	    @Override
   	    protected void configure(HttpSecurity http) throws Exception {
   	    	
   	    	http.csrf().disable(); // We don't need CSRF for Mobile Code based authentication
   	    	http.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
   	    	
   	    }
   	    
   	    @Override
	    public void configure(WebSecurity web) throws Exception {
	    	web.ignoring().antMatchers(identityProperties.getAuthc().getPathPattern());
	    }

   	}

}
