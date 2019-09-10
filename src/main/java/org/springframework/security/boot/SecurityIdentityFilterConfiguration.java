package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProvider;
import org.springframework.security.boot.utils.StringUtils;
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
   	static class IdentityWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {
    	
    	private ApplicationEventPublisher eventPublisher;
    	
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
   	    	
   			IdentityCodeAuthenticationProcessingFilter authcFilter = new IdentityCodeAuthenticationProcessingFilter(
   					objectMapper);
   			
   			authcFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
   			authcFilter.setApplicationEventPublisher(eventPublisher);
   			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
   			authcFilter.setAuthenticationManager(authenticationManager);
   			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
   			authcFilter.setContinueChainBeforeSuccessfulAuthentication(identityProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
   			if (StringUtils.hasText(identityProperties.getAuthc().getPathPattern())) {
   				authcFilter.setFilterProcessesUrl(identityProperties.getAuthc().getPathPattern());
   			}
   			//authcFilter.setMessageSource(messageSource);
   			authcFilter.setMobileParameter(identityProperties.getAuthc().getMobileParameter());
   			authcFilter.setCodeParameter(identityProperties.getAuthc().getCodeParameter());
   			authcFilter.setPostOnly(identityProperties.getAuthc().isPostOnly());
   			authcFilter.setRememberMeServices(rememberMeServices);
   			authcFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
   			
   	        return authcFilter;
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
   	    
   		@Override
   		public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
   			this.eventPublisher = applicationEventPublisher;
   		}

   	}

}
