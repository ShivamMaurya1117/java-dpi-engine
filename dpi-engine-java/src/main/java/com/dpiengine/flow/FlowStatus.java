package com.dpiengine.flow;

/** Observation status, not a full bidirectional TCP connection state machine. */
public enum FlowStatus {
    NEW, ACTIVE, CLOSED
}
