package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityCaptchaProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecurityRedirectProperties;
import org.springframework.security.boot.identity.property.SecurityIdentityAuthcProperties;

@ConfigurationProperties(prefix = SecurityIdentityProperties.PREFIX)
public class SecurityIdentityProperties {

	public static final String PREFIX = "spring.security.identity";

	/** Whether Enable JWT Authentication. */
	private boolean enabled = false;
	@NestedConfigurationProperty
	private SecurityIdentityAuthcProperties authc = new SecurityIdentityAuthcProperties();
	@NestedConfigurationProperty
	private SecurityCaptchaProperties captcha = new SecurityCaptchaProperties();
	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();
	@NestedConfigurationProperty
	private SecurityRedirectProperties redirect = new SecurityRedirectProperties();
	
	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public SecurityIdentityAuthcProperties getAuthc() {
		return authc;
	}

	public void setAuthc(SecurityIdentityAuthcProperties authc) {
		this.authc = authc;
	}

	public SecurityCaptchaProperties getCaptcha() {
		return captcha;
	}

	public void setCaptcha(SecurityCaptchaProperties captcha) {
		this.captcha = captcha;
	}

	public SecurityLogoutProperties getLogout() {
		return logout;
	}

	public void setLogout(SecurityLogoutProperties logout) {
		this.logout = logout;
	}

	public SecurityRedirectProperties getRedirect() {
		return redirect;
	}

	public void setRedirect(SecurityRedirectProperties redirect) {
		this.redirect = redirect;
	}

}
