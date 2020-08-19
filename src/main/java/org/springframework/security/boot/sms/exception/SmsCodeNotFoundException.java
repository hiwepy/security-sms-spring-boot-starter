package org.springframework.security.boot.sms.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

public class SmsCodeNotFoundException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public SmsCodeNotFoundException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED, msg);
	}

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public SmsCodeNotFoundException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED, msg, t);
	}

}
