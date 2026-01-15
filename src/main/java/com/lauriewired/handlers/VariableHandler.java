package com.lauriewired.handlers;

import com.lauriewired.util.DataTypeUtils;
import com.lauriewired.util.ThreadUtils;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.Iterator;

/**
 * Handler for variable-related operations (rename, set type)
 */
public class VariableHandler {

    private final ProgramProvider programProvider;

    public VariableHandler(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    /**
     * Rename data at a specific address
     */
    public void renameDataAtAddress(String addressStr, String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return;

        try {
            ThreadUtils.invokeAndWaitSafe(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        ghidra.program.model.symbol.SymbolTable symTable = program.getSymbolTable();
                        ghidra.program.model.symbol.Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                } catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                } finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    /**
     * Bulk rename data labels at multiple addresses.
     *
     * @param renames List of {address, new_name} pairs
     * @return Result message with success/failure for each rename
     */
    public String bulkRenameData(java.util.List<java.util.Map<String, String>> renames) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (renames == null || renames.isEmpty()) return "Rename list is required";

        StringBuilder result = new StringBuilder();
        final int[] successCount = {0};

        try {
            ThreadUtils.invokeAndWaitSafe(() -> {
                int tx = program.startTransaction("Bulk rename data");
                try {
                    ghidra.program.model.symbol.SymbolTable symTable = program.getSymbolTable();
                    Listing listing = program.getListing();

                    for (java.util.Map<String, String> rename : renames) {
                        String addressStr = rename.get("address");
                        String newName = rename.get("new_name");

                        if (addressStr == null || newName == null) {
                            result.append("SKIP: Invalid entry (missing address or new_name)\n");
                            continue;
                        }

                        try {
                            Address addr = program.getAddressFactory().getAddress(addressStr);
                            ghidra.program.model.symbol.Symbol symbol = symTable.getPrimarySymbol(addr);

                            if (symbol != null) {
                                symbol.setName(newName, SourceType.USER_DEFINED);
                                result.append("OK: ").append(addressStr).append(" -> ").append(newName).append("\n");
                                successCount[0]++;
                            } else {
                                // Try to create a new label
                                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                                result.append("OK (created): ").append(addressStr).append(" -> ").append(newName).append("\n");
                                successCount[0]++;
                            }
                        } catch (Exception e) {
                            result.append("FAIL: ").append(addressStr).append(" - ").append(e.getMessage()).append("\n");
                        }
                    }
                } finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to bulk rename data on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        result.insert(0, "Bulk rename data completed. Success: " + successCount[0] + "/" + renames.size() + "\n");
        return result.toString();
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile");

        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Gets a function at the given address or containing the address
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
     * Compare the given HighFunction's idea of the prototype with the Function's idea.
     * Return true if there is a difference. If a specific symbol is being changed,
     * it can be passed in to check whether or not the prototype is being affected.
     */
    public static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Bulk rename variables within a single function.
     *
     * @param functionAddress Address of the function
     * @param renames List of {old_name, new_name} pairs
     * @return Result message with success/failure for each rename
     */
    public String bulkRenameVariables(String functionAddress, java.util.List<java.util.Map<String, String>> renames) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddress == null || functionAddress.isEmpty()) return "Function address is required";
        if (renames == null || renames.isEmpty()) return "Rename list is required";

        StringBuilder result = new StringBuilder();
        final int[] successCount = {0};

        try {
            ThreadUtils.invokeAndWaitSafe(() -> {
                int tx = program.startTransaction("Bulk rename variables");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    Function func = getFunctionForAddress(program, addr);

                    if (func == null) {
                        result.append("Function not found at: ").append(functionAddress);
                        return;
                    }

                    DecompileResults decompResults = decompileFunction(func, program);
                    if (decompResults == null || !decompResults.decompileCompleted()) {
                        result.append("Decompilation failed for function at: ").append(functionAddress);
                        return;
                    }

                    HighFunction highFunction = decompResults.getHighFunction();
                    if (highFunction == null) {
                        result.append("No high function available");
                        return;
                    }

                    boolean commitRequired = false;

                    for (java.util.Map<String, String> rename : renames) {
                        String oldName = rename.get("old_name");
                        String newName = rename.get("new_name");

                        if (oldName == null || newName == null) {
                            result.append("SKIP: Invalid entry (missing old_name or new_name)\n");
                            continue;
                        }

                        HighSymbol symbol = findSymbolByName(highFunction, oldName);
                        if (symbol == null) {
                            result.append("FAIL: Variable not found: ").append(oldName).append("\n");
                            continue;
                        }

                        // Check if any rename requires commit
                        if (!commitRequired) {
                            commitRequired = checkFullCommit(symbol, highFunction);
                        }

                        try {
                            HighFunctionDBUtil.updateDBVariable(
                                    symbol,
                                    newName,
                                    null,
                                    SourceType.USER_DEFINED
                            );
                            result.append("OK: ").append(oldName).append(" -> ").append(newName).append("\n");
                            successCount[0]++;
                        } catch (Exception e) {
                            result.append("FAIL: ").append(oldName).append(" - ").append(e.getMessage()).append("\n");
                        }
                    }

                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                                HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
                    }
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | java.lang.reflect.InvocationTargetException e) {
            Msg.error(this, "Failed to bulk rename variables on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        result.insert(0, "Bulk rename completed. Success: " + successCount[0] + "/" + renames.size() + "\n");
        return result.toString();
    }

    /**
     * Bulk set variable types within a single function.
     *
     * @param functionAddress Address of the function
     * @param typeChanges List of {variable_name, new_type} pairs
     * @return Result message with success/failure for each type change
     */
    public String bulkSetVariableTypes(String functionAddress, java.util.List<java.util.Map<String, String>> typeChanges) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddress == null || functionAddress.isEmpty()) return "Function address is required";
        if (typeChanges == null || typeChanges.isEmpty()) return "Type change list is required";

        StringBuilder result = new StringBuilder();
        final int[] successCount = {0};

        try {
            ThreadUtils.invokeAndWaitSafe(() -> {
                int tx = program.startTransaction("Bulk set variable types");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    Function func = getFunctionForAddress(program, addr);

                    if (func == null) {
                        result.append("Function not found at: ").append(functionAddress);
                        return;
                    }

                    DecompileResults decompResults = decompileFunction(func, program);
                    if (decompResults == null || !decompResults.decompileCompleted()) {
                        result.append("Decompilation failed for function at: ").append(functionAddress);
                        return;
                    }

                    HighFunction highFunction = decompResults.getHighFunction();
                    if (highFunction == null) {
                        result.append("No high function available");
                        return;
                    }

                    DataTypeManager dtm = program.getDataTypeManager();

                    for (java.util.Map<String, String> change : typeChanges) {
                        String varName = change.get("variable_name");
                        String newTypeName = change.get("new_type");

                        if (varName == null || newTypeName == null) {
                            result.append("SKIP: Invalid entry (missing variable_name or new_type)\n");
                            continue;
                        }

                        HighSymbol symbol = findSymbolByName(highFunction, varName);
                        if (symbol == null) {
                            result.append("FAIL: Variable not found: ").append(varName).append("\n");
                            continue;
                        }

                        DataType dataType = DataTypeUtils.resolveDataType(dtm, newTypeName, programProvider.getTool());
                        if (dataType == null) {
                            result.append("FAIL: Could not resolve type: ").append(newTypeName).append("\n");
                            continue;
                        }

                        try {
                            HighFunctionDBUtil.updateDBVariable(
                                    symbol,
                                    symbol.getName(),
                                    dataType,
                                    SourceType.USER_DEFINED
                            );
                            result.append("OK: ").append(varName).append(" -> ").append(newTypeName).append("\n");
                            successCount[0]++;
                        } catch (Exception e) {
                            result.append("FAIL: ").append(varName).append(" - ").append(e.getMessage()).append("\n");
                        }
                    }
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | java.lang.reflect.InvocationTargetException e) {
            Msg.error(this, "Failed to bulk set variable types on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        result.insert(0, "Bulk type change completed. Success: " + successCount[0] + "/" + typeChanges.size() + "\n");
        return result.toString();
    }

}

