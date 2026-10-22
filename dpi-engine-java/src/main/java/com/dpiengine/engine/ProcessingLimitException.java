package com.dpiengine.engine;

import java.io.IOException;

/** A configured record or flow budget was exceeded. */
public final class ProcessingLimitException extends IOException {
    public ProcessingLimitException(String message) { super(message); }
}
