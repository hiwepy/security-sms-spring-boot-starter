/*
 * Copyright (c) 2018, hiwepy (https://github.com/easy-4-java).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.sms.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.PostOnlyAuthenticationProcessingFilter;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Authentication processing filter for Sms authentication.
 * <p>Intercepts authentication requests and delegates to the authentication manager.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class SmsAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	/**
	 * Constructs a new sms authentication processing filter instance.
	 *
	 * @param objectMapper the object mapper
	 */
	public static final String SPRING_SECURITY_FORM_MOBILE_KEY = "mobile";
    /**
     * Constructs a new sms authentication processing filter instance.
     *
     * @param objectMapper the object mapper
     */
    public static final String SPRING_SECURITY_FORM_CODE_KEY = "code";

    private String mobileParameter = SPRING_SECURITY_FORM_MOBILE_KEY;
    private String codeParameter = SPRING_SECURITY_FORM_CODE_KEY;
	private final ObjectMapper objectMapper;
	
    /**
     * Constructs a new sms authentication processing filter instance.
     *
     * @param objectMapper the object mapper
     */
    public SmsAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(PathPatternRequestMatcher.pathPattern("/login/identity"));
		this.objectMapper = objectMapper;
    }

    /**
     * do Attempt Authentication.
     *
     * @param request the request
     * @param response the response
     * @return the result
     */
    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        
        try {

			AbstractAuthenticationToken authRequest = null;
			// Post && JSON
			if(WebUtils.isObjectRequest(request)) {
				
				SmsLoginRequest loginRequest = objectMapper.readValue(request.getReader(), SmsLoginRequest.class);
		 		authRequest = this.authenticationToken( loginRequest.getMobile(), loginRequest.getCode());
		 		
			} else {
				
				String mobile = obtainMobile(request);
		        String code = obtainCode(request);

		        if (mobile == null) {
		            mobile = "";
		        }

		        if (code == null) {
		            code = "";
		        }
		 		
		 		authRequest = this.authenticationToken( mobile, code);
		 		
			}

			// Allow subclasses to set the "details" property
			setDetails(request, authRequest);

			return this.getAuthenticationManager().authenticate(authRequest);

		} catch (JsonParseException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		} catch (JsonMappingException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		} catch (IOException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		}

    }

    /**
     * obtain Mobile.
     *
     * @param request the request
     * @return the result
     */
    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }

    /**
     * obtain Code.
     *
     * @param request the request
     * @return the result
     */
    protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(codeParameter);
    }

    /**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request,
			AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	/**
	 * authentication Token.
	 *
	 * @param mobile the mobile
	 * @param code the code
	 * @return the result
	 */
	protected AbstractAuthenticationToken authenticationToken(String mobile, String code) {
		return new SmsAuthenticationToken( mobile, code);
	}
    
	/**
	 * Returns the mobile parameter.
	 *
	 * @return the mobile parameter
	 */
	public String getMobileParameter() {
		return mobileParameter;
	}

	/**
	 * Sets the mobile parameter.
	 *
	 * @param mobileParameter the mobile parameter
	 */
	public void setMobileParameter(String mobileParameter) {
		this.mobileParameter = mobileParameter;
	}

	/**
	 * Returns the code parameter.
	 *
	 * @return the code parameter
	 */
	public String getCodeParameter() {
		return codeParameter;
	}

	/**
	 * Sets the code parameter.
	 *
	 * @param codeParameter the code parameter
	 */
	public void setCodeParameter(String codeParameter) {
		this.codeParameter = codeParameter;
	}

}
