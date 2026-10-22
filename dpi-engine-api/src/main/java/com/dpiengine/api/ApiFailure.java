package com.dpiengine.api;

import org.springframework.http.HttpStatus;

final class ApiFailure extends RuntimeException {
    final HttpStatus status;
    ApiFailure(HttpStatus status, String message) { super(message); this.status = status; }
    ApiFailure(HttpStatus status, String message, Throwable cause) { super(message, cause); this.status = status; }
}
