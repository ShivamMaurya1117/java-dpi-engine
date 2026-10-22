package com.dpiengine.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import java.io.IOException;

@RestControllerAdvice
public class ApiErrors extends ResponseEntityExceptionHandler {
    @ExceptionHandler(ApiFailure.class)
    ProblemDetail failure(ApiFailure error) {
        if (error.getSuppressed().length > 0 || (error.getCause() != null && error.getCause().getSuppressed().length > 0)) {
            logger.error("DPI request failed with secondary cleanup/shutdown errors", error);
        }
        return ProblemDetail.forStatusAndDetail(error.status, error.getMessage());
    }
    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail invalidOptions(IllegalArgumentException error) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Invalid blocking rules or worker count");
    }
    @Override
    protected org.springframework.http.ResponseEntity<Object> handleHttpMessageNotReadable(
            org.springframework.http.converter.HttpMessageNotReadableException ex,
            org.springframework.http.HttpHeaders headers, org.springframework.http.HttpStatusCode status,
            org.springframework.web.context.request.WebRequest request) {
        return handleExceptionInternal(ex, ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST,
                "Invalid JSON options: workers must be an integer or null; rules must be arrays of strings; unknown properties are forbidden"),
                headers, HttpStatus.BAD_REQUEST, request);
    }

    @Override
    protected org.springframework.http.ResponseEntity<Object> handleMethodArgumentNotValid(
            org.springframework.web.bind.MethodArgumentNotValidException ex,
            org.springframework.http.HttpHeaders headers, org.springframework.http.HttpStatusCode status,
            org.springframework.web.context.request.WebRequest request) {
        return handleExceptionInternal(ex, ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST,
                "Invalid options: workers must be 1–64 (also subject to the configured API limit); each rule list allows at most 256 nonblank, non-null strings"),
                headers, HttpStatus.BAD_REQUEST, request);
    }
    @ExceptionHandler(IOException.class)
    ProblemDetail io(IOException error) {
        logger.error("DPI request I/O failure", error);
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "PCAP processing or temporary-file I/O failed");
    }
    @Override
    protected org.springframework.http.ResponseEntity<Object> handleMaxUploadSizeExceededException(
            MaxUploadSizeExceededException ex, org.springframework.http.HttpHeaders headers,
            org.springframework.http.HttpStatusCode status, org.springframework.web.context.request.WebRequest request) {
        return handleExceptionInternal(ex, ProblemDetail.forStatusAndDetail(HttpStatus.PAYLOAD_TOO_LARGE,
                "Upload exceeds configured limit"), headers, HttpStatus.PAYLOAD_TOO_LARGE, request);
    }
}
