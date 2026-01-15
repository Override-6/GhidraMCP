package com.lauriewired.handlers;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * Interface for providing the current program to handlers
 */
public interface ProgramProvider {
    Program getCurrentProgram();
    PluginTool getTool();
}
