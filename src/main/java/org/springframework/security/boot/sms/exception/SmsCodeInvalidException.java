package org.springframework.security.boot.sms.exception;

import org.springframework.security.core.AuthenticationException;

public class SmsCodeInvalidException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public SmsCodeInvalidException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public SmsCodeInvalidException(String msg, Throwable t) {
		super(msg, t);
	}

}
