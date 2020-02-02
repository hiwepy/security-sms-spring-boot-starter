package org.springframework.security.boot.sms.exception;

import org.springframework.security.core.AuthenticationException;

public class SmsCodeIncorrectException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public SmsCodeIncorrectException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public SmsCodeIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
}
