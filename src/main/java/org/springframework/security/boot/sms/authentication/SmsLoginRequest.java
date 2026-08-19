package org.springframework.security.boot.sms.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class SmsLoginRequest {

	private String mobile;
	private String code;
	private String captcha;

	/**
	 * Constructs a new sms login request instance.
	 *
	 */
	@JsonCreator
	public SmsLoginRequest(@JsonProperty("mobile") String mobile, @JsonProperty("code") String code,
			@JsonProperty("captcha") String captcha) {
		this.mobile = mobile;
		this.code = code;
		this.captcha = captcha;
	}

	/**
	 * Returns the mobile.
	 *
	 * @return the mobile
	 */
	public String getMobile() {
		return mobile;
	}

	/**
	 * Sets the mobile.
	 *
	 * @param mobile the mobile
	 */
	public void setMobile(String mobile) {
		this.mobile = mobile;
	}

	/**
	 * Returns the code.
	 *
	 * @return the code
	 */
	public String getCode() {
		return code;
	}

	/**
	 * Sets the code.
	 *
	 * @param code the code
	 */
	public void setCode(String code) {
		this.code = code;
	}

	/**
	 * Returns the captcha.
	 *
	 * @return the captcha
	 */
	public String getCaptcha() {
		return captcha;
	}

	/**
	 * Sets the captcha.
	 *
	 * @param captcha the captcha
	 */
	public void setCaptcha(String captcha) {
		this.captcha = captcha;
	}

}
