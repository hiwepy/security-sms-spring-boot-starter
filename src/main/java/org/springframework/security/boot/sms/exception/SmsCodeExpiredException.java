package org.springframework.security.boot.sms.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

public class SmsCodeExpiredException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public SmsCodeExpiredException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED, msg);
	}

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public SmsCodeExpiredException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED, msg, t);
	}

}
