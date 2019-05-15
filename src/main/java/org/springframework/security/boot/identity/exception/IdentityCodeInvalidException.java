package org.springframework.security.boot.identity.exception;

import org.springframework.security.core.AuthenticationException;

public class IdentityCodeInvalidException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public IdentityCodeInvalidException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public IdentityCodeInvalidException(String msg, Throwable t) {
		super(msg, t);
	}

}
