package org.springframework.security.boot.identity.exception;

import org.springframework.security.core.AuthenticationException;

public class IdentityCodeNotFoundException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public IdentityCodeNotFoundException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public IdentityCodeNotFoundException(String msg, Throwable t) {
		super(msg, t);
	}

}
