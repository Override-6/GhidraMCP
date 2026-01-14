package com.lauriewired.model;

/**
 * Class to hold the result of a prototype setting operation
 */
public class PrototypeResult {
    private final boolean success;
    private final String errorMessage;

    public PrototypeResult(boolean success, String errorMessage) {
        this.success = success;
        this.errorMessage = errorMessage;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
