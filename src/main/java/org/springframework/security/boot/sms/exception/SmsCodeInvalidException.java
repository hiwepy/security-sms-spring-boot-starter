package org.springframework.security.boot.sms.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

public class SmsCodeInvalidException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public SmsCodeInvalidException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INVALID, msg);
	}

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public SmsCodeInvalidException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INVALID, msg, t);
	}

}
