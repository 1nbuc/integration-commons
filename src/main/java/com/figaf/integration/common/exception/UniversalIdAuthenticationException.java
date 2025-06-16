package com.figaf.integration.common.exception;

public class UniversalIdAuthenticationException extends RuntimeException {

    public UniversalIdAuthenticationException(String message) {
        super(message);
    }

    public UniversalIdAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
