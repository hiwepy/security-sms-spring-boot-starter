package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
@AutoConfigureAfter(SecurityBizFilterAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityIdentityProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityIdentityProperties.class })
@Order(106)
public class SecurityIdentityFilterConfiguration extends WebSecurityConfigurerAdapter  implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	
	@Autowired
	private SecurityIdentityProperties identityProperties;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private RememberMeServices rememberMeServices;
	@Autowired
    private SessionRegistry sessionRegistry;
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	@Qualifier("idcAuthenticatingFailureCounter")
	private AuthenticatingFailureCounter idcAuthenticatingFailureCounter;
	@Autowired
	@Qualifier("idcSessionAuthenticationStrategy")
	private SessionAuthenticationStrategy idcSessionAuthenticationStrategy;
    @Autowired
    @Qualifier("idcCsrfTokenRepository")
	private CsrfTokenRepository idcCsrfTokenRepository;
    @Autowired
    @Qualifier("idcExpiredSessionStrategy")
    private SessionInformationExpiredStrategy idcExpiredSessionStrategy;
    @Autowired
    @Qualifier("idcRequestCache")
    private RequestCache idcRequestCache;
    @Autowired
    @Qualifier("idcInvalidSessionStrategy")
    private InvalidSessionStrategy idcInvalidSessionStrategy;
    @Autowired
    @Qualifier("idcSecurityContextLogoutHandler") 
    private SecurityContextLogoutHandler idcSecurityContextLogoutHandler;
    @Autowired
	private IdentityCodeAuthenticationSuccessHandler identityCodeAuthenticationSuccessHandler;
	@Autowired
	private IdentityCodeAuthenticationFailureHandler identityCodeAuthenticationFailureHandler;
    @Autowired
    private IdentityCodeAuthenticationProvider identityCodeAuthenticationProvider;
    @Autowired
    private IdentityCodeAuthenticationEntryPoint identityCodeAuthenticationEntryPoint;

    @Bean
    public IdentityCodeAuthenticationProcessingFilter identityCodeAuthenticationProcessingFilter() {
    	
		IdentityCodeAuthenticationProcessingFilter authcFilter = new IdentityCodeAuthenticationProcessingFilter(
				objectMapper);
		
		authcFilter.setAllowSessionCreation(identityProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(identityCodeAuthenticationFailureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(identityCodeAuthenticationSuccessHandler);
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(identityProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
		if (StringUtils.hasText(identityProperties.getAuthc().getLoginUrlPatterns())) {
			authcFilter.setFilterProcessesUrl(identityProperties.getAuthc().getLoginUrlPatterns());
		}
		//authcFilter.setMessageSource(messageSource);
		authcFilter.setMobileParameter(identityProperties.getAuthc().getMobileParameter());
		authcFilter.setCodeParameter(identityProperties.getAuthc().getCodeParameter());
		authcFilter.setPostOnly(identityProperties.getAuthc().isPostOnly());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setSessionAuthenticationStrategy(idcSessionAuthenticationStrategy);
		
        return authcFilter;
    }
	 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(identityCodeAuthenticationProvider)
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
    		.invalidSessionStrategy(idcInvalidSessionStrategy)
    		.invalidSessionUrl(identityProperties.getLogout().getLogoutUrl())
    		.maximumSessions(sessionMgt.getMaximumSessions())
    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
    		.expiredSessionStrategy(idcExpiredSessionStrategy)
			.expiredUrl(identityProperties.getLogout().getLogoutUrl())
			.sessionRegistry(sessionRegistry)
			.and()
    		.sessionAuthenticationErrorUrl(identityProperties.getAuthc().getFailureUrl())
    		.sessionAuthenticationFailureHandler(identityCodeAuthenticationFailureHandler)
    		.sessionAuthenticationStrategy(idcSessionAuthenticationStrategy)
    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
    		// Session 注销配置
    		.and()
    		.logout()
    		.addLogoutHandler(idcSecurityContextLogoutHandler)
    		.clearAuthentication(logout.isClearAuthentication())
        	// Request 缓存配置
        	.and()
    		.requestCache()
        	.requestCache(idcRequestCache)
        	.and()
			.addFilterBefore(identityCodeAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
        
        http.exceptionHandling().authenticationEntryPoint(identityCodeAuthenticationEntryPoint);
        
    }

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
