package org.springframework.security.boot.sms.exception;

import org.springframework.security.core.AuthenticationException;

public class SmsCodeNotFoundException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public SmsCodeNotFoundException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public SmsCodeNotFoundException(String msg, Throwable t) {
		super(msg, t);
	}

}
