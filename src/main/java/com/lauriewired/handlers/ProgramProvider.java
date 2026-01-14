package com.lauriewired.handlers;

import ghidra.program.model.listing.Program;

/**
 * Interface for providing the current program to handlers
 */
@FunctionalInterface
public interface ProgramProvider {
    Program getCurrentProgram();
}
