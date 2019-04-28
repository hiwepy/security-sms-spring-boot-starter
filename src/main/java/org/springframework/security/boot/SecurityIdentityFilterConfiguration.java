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
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationEntryPoint;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationFailureHandler;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationProvider;
import org.springframework.security.boot.identity.authentication.IdentityCodeAuthenticationSuccessHandler;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties({ SecurityIdentityProperties.class })
public class SecurityIdentityFilterConfiguration {
    
    @Configuration
    @ConditionalOnProperty(prefix = SecurityIdentityProperties.PREFIX, value = "enabled", havingValue = "true")
   	@EnableConfigurationProperties({ SecurityIdentityProperties.class, SecurityBizProperties.class })
    @Order(106)
   	static class IdentityWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {
    	
    	private ApplicationEventPublisher eventPublisher;
    	
        private final AuthenticationManager authenticationManager;
	    private final ObjectMapper objectMapper;
	    private final PasswordEncoder passwordEncoder;
	    private final RememberMeServices rememberMeServices;
	    private final SessionRegistry sessionRegistry;
		private final UserDetailsService userDetailsService;
		
    	private final SecurityIdentityProperties identityProperties;
    	private final IdentityCodeAuthenticationProvider authenticationProvider;
	    private final IdentityCodeAuthenticationEntryPoint authenticationEntryPoint;
	    private final IdentityCodeAuthenticationProcessingFilter authenticationProcessingFilter;
	    private final IdentityCodeAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final IdentityCodeAuthenticationFailureHandler authenticationFailureHandler;
	    
	    private final InvalidSessionStrategy invalidSessionStrategy;
    	private final RequestCache requestCache;
		private final SecurityContextLogoutHandler securityContextLogoutHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy expiredSessionStrategy;
   		
   		public IdentityWebSecurityConfigurerAdapter(
   			
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<PasswordEncoder> passwordEncoderProvider,
   				ObjectProvider<SessionRegistry> sessionRegistryProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				ObjectProvider<UserDetailsService> userDetailsServiceProvider,
   				SecurityIdentityProperties identityProperties,
   				ObjectProvider<IdentityCodeAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<IdentityCodeAuthenticationProvider> authenticationProvider,
   				ObjectProvider<IdentityCodeAuthenticationProcessingFilter> authenticationProcessingFilter,
   				ObjectProvider<IdentityCodeAuthenticationSuccessHandler> authenticationSuccessHandler,
   				ObjectProvider<IdentityCodeAuthenticationFailureHandler> authenticationFailureHandler,
   				
   				@Qualifier("idcAuthenticatingFailureCounter") ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
   				@Qualifier("idcCsrfTokenRepository") ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				@Qualifier("idcInvalidSessionStrategy") ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
				@Qualifier("idcRequestCache") ObjectProvider<RequestCache> requestCacheProvider,
				@Qualifier("idcSecurityContextLogoutHandler")  ObjectProvider<SecurityContextLogoutHandler> securityContextLogoutHandlerProvider,
				@Qualifier("idcSessionAuthenticationStrategy") ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				@Qualifier("idcExpiredSessionStrategy") ObjectProvider<SessionInformationExpiredStrategy> expiredSessionStrategyProvider
				) {
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.passwordEncoder = passwordEncoderProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
   			this.userDetailsService = userDetailsServiceProvider.getIfAvailable();
   			
   			this.identityProperties = identityProperties;
   			this.authenticationEntryPoint = authenticationEntryPointProvider.getIfAvailable();
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationProcessingFilter = authenticationProcessingFilter.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			
   			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
   			this.requestCache = requestCacheProvider.getIfAvailable();
   			this.securityContextLogoutHandler = securityContextLogoutHandlerProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			this.expiredSessionStrategy = expiredSessionStrategyProvider.getIfAvailable();
   			
   		}

   		@Bean
   	    public IdentityCodeAuthenticationProcessingFilter identityCodeAuthenticationProcessingFilter() {
   	    	
   			IdentityCodeAuthenticationProcessingFilter authcFilter = new IdentityCodeAuthenticationProcessingFilter(
   					objectMapper);
   			
   			authcFilter.setAllowSessionCreation(identityProperties.getSessionMgt().isAllowSessionCreation());
   			authcFilter.setApplicationEventPublisher(eventPublisher);
   			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
   			authcFilter.setAuthenticationManager(authenticationManager);
   			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
   			authcFilter.setContinueChainBeforeSuccessfulAuthentication(identityProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
   			if (StringUtils.hasText(identityProperties.getAuthc().getLoginUrlPatterns())) {
   				authcFilter.setFilterProcessesUrl(identityProperties.getAuthc().getLoginUrlPatterns());
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
   	        auth.authenticationProvider(authenticationProvider)
   		    	.userDetailsService(userDetailsService)
   		    	.passwordEncoder(passwordEncoder);
   	    }

   	    @Override
   	    protected void configure(HttpSecurity http) throws Exception {
   	    	
   	    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
   	    	
   	    	// Session 管理器配置参数
   	    	SecuritySessionMgtProperties sessionMgt = identityProperties.getSessionMgt();
   	    	// Session 注销配置参数
   	    	SecurityLogoutProperties logout = identityProperties.getLogout();
   	    	
   		    // Session 管理器配置
   	    	http.sessionManagement()
   	    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
   	    		.invalidSessionStrategy(invalidSessionStrategy)
   	    		.invalidSessionUrl(identityProperties.getLogout().getLogoutUrl())
   	    		.maximumSessions(sessionMgt.getMaximumSessions())
   	    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
   	    		.expiredSessionStrategy(expiredSessionStrategy)
   				.expiredUrl(identityProperties.getLogout().getLogoutUrl())
   				.sessionRegistry(sessionRegistry)
   				.and()
   	    		.sessionAuthenticationErrorUrl(identityProperties.getAuthc().getFailureUrl())
   	    		.sessionAuthenticationFailureHandler(authenticationFailureHandler)
   	    		.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
   	    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
   	    		// Session 注销配置
   	    		.and()
   	    		.logout()
   	    		.addLogoutHandler(securityContextLogoutHandler)
   	    		.clearAuthentication(logout.isClearAuthentication())
   	        	// Request 缓存配置
   	        	.and()
   	    		.requestCache()
   	        	.requestCache(requestCache)
   	        	.and()
   				.addFilterBefore(authenticationProcessingFilter, UsernamePasswordAuthenticationFilter.class);
   	        
   	        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
   	        
   	    }
   	    
   		@Override
   		public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
   			this.eventPublisher = applicationEventPublisher;
   		}

   	}

}
