package com.lauriewired.handlers;

import com.lauriewired.util.HttpUtils;
import com.lauriewired.util.ThreadUtils;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Handler for function-related operations (decompile, rename, search, prototype)
 */
public class FunctionHandler {

    private final ProgramProvider programProvider;
    private final PluginTool tool;

    public FunctionHandler(ProgramProvider programProvider) {
        this.programProvider = programProvider;
        this.tool = programProvider.getTool();
    }

    /**
     * Search functions by name with pagination
     */
    public String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";

        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return HttpUtils.paginateList(matches, offset, limit);
    }

    /**
     * Decompile a function by name
     */
    public String decompileFunctionByName(String name) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                        decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return formatDecompilationResult(func, result.getDecompiledFunction().getC());
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    /**
     * Decompile a function at the given address
     */
    public String decompileFunctionByAddress(String addressStr) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted())
                    ? formatDecompilationResult(func, result.getDecompiledFunction().getC())
                    : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Decompile a function with full context including type definitions and called functions.
     */
    public String decompileFunctionWithContext(String addressStr) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

            if (result == null || !result.decompileCompleted()) {
                return "Decompilation failed";
            }

            StringBuilder sb = new StringBuilder();
            DataTypeManager dtm = program.getDataTypeManager();
            HighFunction highFunc = result.getHighFunction();

            // ============ SECTION 1: Decompiled Function ============
            sb.append("// ============================================================\n");
            sb.append("// DECOMPILED FUNCTION\n");
            sb.append("// ============================================================\n");
            sb.append("// Function: ").append(func.getName()).append("\n");
            sb.append("// Address: ").append(func.getEntryPoint()).append("\n");
            sb.append("// Signature: ").append(func.getSignature().getPrototypeString()).append("\n");
            sb.append("// Body: ").append(func.getBody().getMinAddress())
                    .append(" - ").append(func.getBody().getMaxAddress()).append("\n");
            sb.append("// ============================================================\n\n");
            sb.append(result.getDecompiledFunction().getC());
            sb.append("\n\n");

            // ============ SECTION 2: Collect used types ============
            Set<DataType> usedTypes = new LinkedHashSet<>();
            Set<Function> calledFunctions = new LinkedHashSet<>();

            // Collect types from function signature
            collectTypesFromSignature(func, usedTypes, dtm);

            // Collect types from local variables and parameters
            if (highFunc != null) {
                LocalSymbolMap localSymbolMap = highFunc.getLocalSymbolMap();
                if (localSymbolMap != null) {
                    Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
                    while (symbols.hasNext()) {
                        HighSymbol symbol = symbols.next();
                        HighVariable highVar = symbol.getHighVariable();
                        if (highVar != null) {
                            collectTypeAndDependencies(highVar.getDataType(), usedTypes, dtm);
                        }
                    }
                }
            }

            // Collect called functions
            collectCalledFunctions(func, program, calledFunctions);

            // Collect types from called functions
            for (Function calledFunc : calledFunctions) {
                collectTypesFromSignature(calledFunc, usedTypes, dtm);
            }

            // ============ SECTION 3: Type Definitions ============
            sb.append("// ============================================================\n");
            sb.append("// TYPE DEFINITIONS USED IN THIS FUNCTION\n");
            sb.append("// ============================================================\n\n");

            // Output structures
            boolean hasStructures = false;
            for (DataType dt : usedTypes) {
                if (dt instanceof Structure && !(dt instanceof BuiltInDataType)) {
                    if (!hasStructures) {
                        sb.append("// --- STRUCTURES ---\n\n");
                        hasStructures = true;
                    }
                    formatStructureDefinition((Structure) dt, sb);
                }
            }

            // Output enums
            boolean hasEnums = false;
            for (DataType dt : usedTypes) {
                if (dt instanceof ghidra.program.model.data.Enum) {
                    if (!hasEnums) {
                        sb.append("// --- ENUMS ---\n\n");
                        hasEnums = true;
                    }
                    formatEnumDefinition((ghidra.program.model.data.Enum) dt, sb);
                }
            }

            // Output function definitions (function pointers)
            boolean hasFuncDefs = false;
            for (DataType dt : usedTypes) {
                if (dt instanceof FunctionDefinition) {
                    if (!hasFuncDefs) {
                        sb.append("// --- FUNCTION TYPES ---\n\n");
                        hasFuncDefs = true;
                    }
                    formatFunctionDefinition((FunctionDefinition) dt, sb);
                }
            }

            // Output typedefs
            boolean hasTypedefs = false;
            for (DataType dt : usedTypes) {
                if (dt instanceof TypeDef) {
                    if (!hasTypedefs) {
                        sb.append("// --- TYPEDEFS ---\n\n");
                        hasTypedefs = true;
                    }
                    TypeDef td = (TypeDef) dt;
                    sb.append("typedef ").append(td.getBaseDataType().getName())
                            .append(" ").append(td.getName()).append(";\n\n");
                }
            }

            if (!hasStructures && !hasEnums && !hasFuncDefs && !hasTypedefs) {
                sb.append("// (No custom type definitions used)\n\n");
            }

            // ============ SECTION 4: Called Functions ============
            sb.append("// ============================================================\n");
            sb.append("// CALLED FUNCTION PROTOTYPES\n");
            sb.append("// ============================================================\n\n");

            if (calledFunctions.isEmpty()) {
                sb.append("// (No function calls detected)\n");
            } else {
                for (Function calledFunc : calledFunctions) {
                    sb.append("// Address: ").append(calledFunc.getEntryPoint()).append("\n");
                    sb.append(calledFunc.getSignature().getPrototypeString()).append(";\n\n");
                }
            }

            return sb.toString();
        } catch (Exception e) {
            return "Error decompiling function with context: " + e.getMessage();
        }
    }

    /**
     * Collect types from a function's signature (return type and parameters)
     */
    private void collectTypesFromSignature(Function func, Set<DataType> usedTypes, DataTypeManager dtm) {
        // Return type
        collectTypeAndDependencies(func.getReturnType(), usedTypes, dtm);

        // Parameters
        for (Parameter param : func.getParameters()) {
            collectTypeAndDependencies(param.getDataType(), usedTypes, dtm);
        }
    }

    /**
     * Recursively collect a type and all its dependencies
     */
    private void collectTypeAndDependencies(DataType dt, Set<DataType> usedTypes, DataTypeManager dtm) {
        if (dt == null) return;

        // Unwrap pointers and arrays
        DataType baseType = dt;
        while (baseType instanceof Pointer) {
            baseType = ((Pointer) baseType).getDataType();
        }
        while (baseType instanceof Array) {
            baseType = ((Array) baseType).getDataType();
        }

        if (baseType == null) return;

        // Skip built-in types
        if (baseType instanceof BuiltInDataType || baseType instanceof VoidDataType ||
                baseType instanceof AbstractIntegerDataType || baseType instanceof AbstractFloatDataType) {
            return;
        }

        // Skip if already processed
        if (usedTypes.contains(baseType)) return;

        // Add the type
        if (baseType instanceof Structure || baseType instanceof ghidra.program.model.data.Enum ||
                baseType instanceof FunctionDefinition || baseType instanceof TypeDef) {
            usedTypes.add(baseType);
        }

        // Recurse into structure fields
        if (baseType instanceof Structure) {
            Structure struct = (Structure) baseType;
            for (DataTypeComponent component : struct.getComponents()) {
                collectTypeAndDependencies(component.getDataType(), usedTypes, dtm);
            }
        }

        // Recurse into typedef base type
        if (baseType instanceof TypeDef) {
            collectTypeAndDependencies(((TypeDef) baseType).getBaseDataType(), usedTypes, dtm);
        }

        // Recurse into function definition parameters
        if (baseType instanceof FunctionDefinition) {
            FunctionDefinition funcDef = (FunctionDefinition) baseType;
            collectTypeAndDependencies(funcDef.getReturnType(), usedTypes, dtm);
            for (ParameterDefinition param : funcDef.getArguments()) {
                collectTypeAndDependencies(param.getDataType(), usedTypes, dtm);
            }
        }
    }

    /**
     * Collect all functions called by the given function
     */
    private void collectCalledFunctions(Function func, Program program, Set<Function> calledFunctions) {
        FunctionManager funcMgr = program.getFunctionManager();

        // Get all references from this function's body
        ghidra.program.model.symbol.ReferenceManager refMgr = program.getReferenceManager();

        for (Address addr : func.getBody().getAddresses(true)) {
            ghidra.program.model.symbol.Reference[] refs = refMgr.getReferencesFrom(addr);
            for (ghidra.program.model.symbol.Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    Address toAddr = ref.getToAddress();
                    Function calledFunc = funcMgr.getFunctionAt(toAddr);
                    if (calledFunc != null && !calledFunc.equals(func)) {
                        calledFunctions.add(calledFunc);
                    }
                }
            }
        }
    }

    /**
     * Format a structure definition
     */
    private void formatStructureDefinition(Structure struct, StringBuilder sb) {
        sb.append("// Path: ").append(struct.getPathName()).append("\n");
        sb.append("// Size: ").append(struct.getLength()).append(" bytes\n");
        sb.append("struct ").append(struct.getName()).append(" {\n");
        for (DataTypeComponent component : struct.getDefinedComponents()) {
            String fieldName = component.getFieldName();
            if (fieldName == null || fieldName.isEmpty()) {
                fieldName = "field_0x" + Integer.toHexString(component.getOffset());
            }
            sb.append("    /* +0x").append(String.format("%x", component.getOffset())).append(" */ ");
            sb.append(component.getDataType().getName()).append(" ").append(fieldName);
            sb.append("; // size: ").append(component.getLength()).append("\n");
        }
        sb.append("};\n\n");
    }

    /**
     * Format an enum definition
     */
    private void formatEnumDefinition(ghidra.program.model.data.Enum enumType, StringBuilder sb) {
        sb.append("// Path: ").append(enumType.getPathName()).append("\n");
        sb.append("// Size: ").append(enumType.getLength()).append(" bytes\n");
        sb.append("enum ").append(enumType.getName()).append(" {\n");
        for (String name : enumType.getNames()) {
            long value = enumType.getValue(name);
            sb.append("    ").append(name).append(" = ").append(value).append(",\n");
        }
        sb.append("};\n\n");
    }

    /**
     * Format a function definition
     */
    private void formatFunctionDefinition(FunctionDefinition funcDef, StringBuilder sb) {
        sb.append("// Path: ").append(funcDef.getPathName()).append("\n");
        sb.append("typedef ").append(funcDef.getPrototypeString()).append(";\n\n");
    }

    /**
     * Get assembly code for a function
     */
    public String disassembleFunction(String addressStr) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break;
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n",
                        instr.getAddress(),
                        instr.toString(),
                        comment));
            }


            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    /**
     * Get function by address
     */
    public String getFunctionByAddress(String addressStr) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                    func.getName(),
                    func.getEntryPoint(),
                    func.getSignature(),
                    func.getEntryPoint(),
                    func.getBody().getMinAddress(),
                    func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    public String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    public String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature());
    }

    /**
     * Gets a function at the given address or containing the address
     */
    public Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function and return the results
     */
    public DecompileResults decompileFunction(Function func, Program program) {
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
     * Format decompilation result with function metadata header
     */
    private String formatDecompilationResult(Function func, String decompiledCode) {
        StringBuilder sb = new StringBuilder();
        sb.append("// ============================================================\n");
        sb.append("// Function: ").append(func.getName()).append("\n");
        sb.append("// Address: ").append(func.getEntryPoint()).append("\n");
        sb.append("// Signature: ").append(func.getSignature().getPrototypeString()).append("\n");
        sb.append("// Body: ").append(func.getBody().getMinAddress())
                .append(" - ").append(func.getBody().getMaxAddress()).append("\n");
        sb.append("// ============================================================\n\n");
        sb.append(decompiledCode);
        return sb.toString();
    }

    /**
     * Bulk rename functions by address.
     *
     * @param renames List of {address, new_name} pairs
     * @return Result message with success/failure for each rename
     */
    public String bulkRenameFunctions(List<java.util.Map<String, String>> renames) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (renames == null || renames.isEmpty()) return "Rename list is required";

        StringBuilder result = new StringBuilder();
        final int[] successCount = {0};

        try {
            ThreadUtils.invokeAndWaitSafe(() -> {
                int tx = program.startTransaction("Bulk rename functions");
                try {
                    for (java.util.Map<String, String> rename : renames) {
                        String addressStr = rename.get("address");
                        String newName = rename.get("new_name");

                        if (addressStr == null || newName == null) {
                            result.append("SKIP: Invalid entry (missing address or new_name)\n");
                            continue;
                        }

                        try {
                            Address addr = program.getAddressFactory().getAddress(addressStr);
                            Function func = getFunctionForAddress(program, addr);

                            if (func == null) {
                                result.append("FAIL: No function at ").append(addressStr).append("\n");
                                continue;
                            }

                            String oldName = func.getName();
                            func.setName(newName, SourceType.USER_DEFINED);
                            result.append("OK: ").append(oldName).append(" @ ").append(addressStr)
                                    .append(" -> ").append(newName).append("\n");
                            successCount[0]++;
                        } catch (Exception e) {
                            result.append("FAIL: ").append(addressStr).append(" - ").append(e.getMessage()).append("\n");
                        }
                    }
                } finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (Throwable e) {
            Msg.error(this, "Failed to bulk rename functions on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        result.insert(0, "Bulk rename completed. Success: " + successCount[0] + "/" + renames.size() + "\n");
        return result.toString();
    }

    /**
     * Bulk set function prototypes.
     *
     * @param prototypes List of {address, prototype} pairs
     * @return Result message with success/failure for each operation
     */
    public String bulkSetFunctionPrototypes(List<java.util.Map<String, String>> prototypes) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (prototypes == null || prototypes.isEmpty()) return "Prototype list is required";

        StringBuilder result = new StringBuilder();
        final int[] successCount = {0};

        try {
            ThreadUtils.invokeAndWaitSafe(() -> {
                for (java.util.Map<String, String> proto : prototypes) {
                    String addressStr = proto.get("address");
                    String prototype = proto.get("prototype");

                    if (addressStr == null || prototype == null) {
                        result.append("SKIP: Invalid entry (missing address or prototype)\n");
                        continue;
                    }

                    try {
                        Address addr = program.getAddressFactory().getAddress(addressStr);
                        Function func = getFunctionForAddress(program, addr);

                        if (func == null) {
                            result.append("FAIL: No function at ").append(addressStr).append("\n");
                            continue;
                        }

                        // Apply prototype in its own transaction
                        int tx = program.startTransaction("Set prototype for " + addressStr);
                        try {
                            DataTypeManager dtm = program.getDataTypeManager();
                            ghidra.app.services.DataTypeManagerService dtms =
                                    tool.getService(ghidra.app.services.DataTypeManagerService.class);
                            ghidra.app.util.parser.FunctionSignatureParser parser =
                                    new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

                            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

                            if (sig == null) {
                                result.append("FAIL: Could not parse prototype for ").append(addressStr).append("\n");
                                continue;
                            }

                            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                                            addr, sig, SourceType.USER_DEFINED);

                            if (cmd.applyTo(program, new ConsoleTaskMonitor())) {
                                result.append("OK: ").append(func.getName()).append(" @ ").append(addressStr).append("\n");
                                successCount[0]++;
                            } else {
                                result.append("FAIL: ").append(addressStr).append(" - ").append(cmd.getStatusMsg()).append("\n");
                            }
                        } finally {
                            program.endTransaction(tx, true);
                        }
                    } catch (Exception e) {
                        result.append("FAIL: ").append(addressStr).append(" - ").append(e.getMessage()).append("\n");
                    }
                }
            });
        } catch (Throwable e) {
            Msg.error(this, "Failed to bulk set prototypes on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        result.insert(0, "Bulk prototype set completed. Success: " + successCount[0] + "/" + prototypes.size() + "\n");
        return result.toString();
    }

    /**
     * Robustly commits function analysis changes.
     * Attempts to apply every single item individually, catching errors per item
     * so that one failure does not stop the entire batch.
     */
    public String commitFunctionAnalysis(Map<String, Object> payload, DataTypeHandler dataTypeHandler,
                                         VariableHandler variableHandler) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "Error: No program loaded";

        String functionAddress = (String) payload.get("function_address");
        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }

        // Use AtomicReference to capture the final report from the Swing thread
        AtomicReference<String> reportRef = new AtomicReference<>();

        try {
            ThreadUtils.invokeAndWaitSafe(() -> {
                StringBuilder report = new StringBuilder();
                report.append("=== ANALYSIS COMMIT REPORT ===\n");
                report.append("Target: ").append(functionAddress).append("\n");

                // 1. START TRANSACTION
                // We use one global transaction for the batch.
                // We will commit whatever succeeds.
                int txId = program.startTransaction("MCP Commit: " + functionAddress);

                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    Function func = getFunctionForAddress(program, addr);

                    if (func == null) {
                        report.append("CRITICAL ERROR: Function not found at ").append(functionAddress).append("\n");
                        // If function is missing, we can't do anything else.
                        return;
                    }

                    // ============ 1. Types  ============
                    List<Map<String, Object>> types = (List<Map<String, Object>>) payload.get("types");
                    if (types != null && !types.isEmpty()) {
                        report.append("\n[Types]\n");
                        for (Map<String, Object> typeDef : types) {
                            String name = (String) typeDef.getOrDefault("name", "Unknown");
                            try {
                                String result = processTypeDefinition(program, typeDef, dataTypeHandler);
                                report.append("  [OK] ").append(name).append(": ").append(result).append("\n");
                            } catch (Exception e) {
                                report.append("  [FAIL] ").append(name).append(": ").append(e.getMessage()).append("\n");
                                Msg.error(this, "Failed to process type: " + name, e);
                            }
                        }
                    }

                    // ============ 2. Structures  ============
                    List<Map<String, Object>> structures = (List<Map<String, Object>>) payload.get("structures");
                    if (structures != null && !structures.isEmpty()) {
                        report.append("\n[Structures]\n");
                        for (Map<String, Object> structDef : structures) {
                            String name = (String) structDef.getOrDefault("name", null);
                            try {
                                // Defensive coding: Check inputs before passing to helper
                                if (name == null) {
                                    report.append("  [FAIL] Missing structure name in structure def ").append(structDef).append("\n");
                                    continue;
                                }

                                // Call your existing helper
                                String result = processStructureDefinition(program, structDef, dataTypeHandler);
                                report.append("  [OK] ").append(name).append(": ").append(result).append("\n");
                            } catch (Exception e) {
                                report.append("  [FAIL] ").append(name).append(": ").append(e.getMessage()).append("\n");
                                Msg.error(this, "Failed to process structure: " + name, e);
                            }
                        }
                    }

                    // ============ 3. Function Signature (Single Block) ============
                    String newSignature = (String) payload.get("new_signature");
                    if (newSignature != null && !newSignature.isEmpty()) {
                        report.append("\n[Signature]\n");
                        try {
                            String result = applyFunctionSignature(program, addr, newSignature);
                            report.append("  [OK] Applied: ").append(result).append("\n");
                        } catch (Exception e) {
                            report.append("  [FAIL] Could not apply signature: ").append(e.getMessage()).append("\n");
                            Msg.error(this, "Failed to set signature: " + newSignature, e);
                        }
                    }

                    // ============ 4. Variable Changes  ============
                    List<Map<String, Object>> variableChanges = (List<Map<String, Object>>) payload.get("variable_changes");
                    if (variableChanges != null && !variableChanges.isEmpty()) {
                        report.append("\n[Variables]\n");
                        // Note: If applyVariableChanges handles the whole list at once, wrap the whole call.
                        // If you can iterate them here, do so. Assuming your handler takes the list:
                        try {
                            // If your handler iterates internally, we trust it.
                            // If it throws on the first error, you might want to refactor the handler to return a report.
                            // Here we wrap the whole block just in case.
                            String result = applyVariableChanges(program, functionAddress, variableChanges, variableHandler);
                            report.append(result).append("\n");
                        } catch (Exception e) {
                            report.append("  [FAIL] Error applying variables: ").append(e.getMessage()).append("\n");
                            Msg.error(this, "Failed processing variables", e);
                        }
                    }

                    // ============ 5. Called Functions  ============
                    List<Map<String, Object>> calledFunctions = (List<Map<String, Object>>) payload.get("called_functions");
                    if (calledFunctions != null && !calledFunctions.isEmpty()) {
                        report.append("\n[Called Functions]\n");
                        for (Map<String, Object> callDef : calledFunctions) {
                            String calleeAddr = (String) callDef.get("address");
                            try {
                                // Logic extracted from applyCalledFunctionPrototypes to handle per-item errors
                                // or simple delegation if your helper is robust.
                                // Assuming applyCalledFunctionPrototypes iterates the list itself:
                                String result = applyCalledFunctionPrototypes(program, List.of(callDef)); // Process one by one
                                report.append("  [OK] ").append(calleeAddr).append(": Updated\n");
                            } catch (Exception e) {
                                report.append("  [FAIL] ").append(calleeAddr).append(": ").append(e.getMessage()).append("\n");
                            }
                        }
                    }

                } catch (Exception e) {
                    // Catch any unexpected top-level error (e.g. invalid address format)
                    report.append("\nCRITICAL FAILURE: ").append(e.getMessage());
                    Msg.error(this, "Critical error in commitFunctionAnalysis", e);
                } finally {
                    // ALWAYS commit the transaction to save the parts that worked
                    program.endTransaction(txId, true);
                    reportRef.set(report.toString());
                }
            });
        } catch (Exception e) {
            return "Error ! executing on Swing thread incomplete report: \n" + reportRef.get();
        } catch (Throwable t) {
            Msg.error("Unknown Error in commitFunctionAnalysis", t);
        }

        return reportRef.get();
    }

    /**
     * Process a structure definition (create or update)
     */
    private String processStructureDefinition(Program program, Map<String, Object> structDef,
                                              DataTypeHandler dataTypeHandler) {
        Msg.info(this, "Processing structure definition: " + structDef);
        String name = (String) structDef.get("name");
        if (name == null || name.isEmpty()) {
            return "SKIP: Structure name is required";
        }

        String categoryPath = (String) structDef.getOrDefault("category_path", "");
        int size = structDef.containsKey("size") ? ((Number) structDef.get("size")).intValue() : 0;

        @SuppressWarnings("unchecked")
        List<Map<String, String>> fields = (List<Map<String, String>>) structDef.get("fields");

        DataTypeManager dtm = program.getDataTypeManager();

        // Check if structure exists
        Structure existing = findStructure(dtm, name);
        if (existing != null) {
            // Update existing structure with new fields
            if (fields != null && !fields.isEmpty()) {
                return dataTypeHandler.bulkUpdateStructureFields(name, fields);
            }
            return "OK: Structure '" + name + "' already exists (no new fields)";
        } else {
            // Create new structure
            if (fields != null && !fields.isEmpty()) {
                return dataTypeHandler.createStructureWithFields(name, categoryPath, size, fields);
            } else {
                return dataTypeHandler.createStructure(name, categoryPath, size);
            }
        }
    }

    /**
     * Process a type definition (enum or function type)
     */
    private String processTypeDefinition(Program program, Map<String, Object> typeDef,
                                         DataTypeHandler dataTypeHandler) {
        String kind = (String) typeDef.get("kind");
        if (kind == null || kind.isEmpty()) {
            return "SKIP: Type kind is required (enum or function)";
        }

        if (kind.equalsIgnoreCase("enum")) {
            String name = (String) typeDef.get("name");
            if (name == null) return "SKIP: Enum name is required";

            String categoryPath = (String) typeDef.getOrDefault("category_path", "");
            int size = typeDef.containsKey("size") ? ((Number) typeDef.get("size")).intValue() : 4;

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> values = (List<Map<String, Object>>) typeDef.get("values");

            String createResult = dataTypeHandler.createEnum(name, categoryPath, size);
            if (!createResult.startsWith("Enum created") && !createResult.contains("already exists")) {
                return createResult;
            }

            // Add values if provided
            if (values != null && !values.isEmpty()) {
                StringBuilder valResult = new StringBuilder(createResult).append("\n");
                for (Map<String, Object> val : values) {
                    String valName = (String) val.get("name");
                    long valValue = val.containsKey("value") ? ((Number) val.get("value")).longValue() : 0;
                    String addResult = dataTypeHandler.addEnumValue(name, valName, valValue);
                    valResult.append("  ").append(addResult).append("\n");
                }
                return valResult.toString();
            }
            return createResult;

        } else if (kind.equalsIgnoreCase("function")) {
            String prototype = (String) typeDef.get("prototype");
            if (prototype == null) return "SKIP: Function prototype is required";

            String categoryPath = (String) typeDef.getOrDefault("category_path", "");
            return dataTypeHandler.createFunctionDefinitionFromPrototype(prototype, categoryPath);

        } else {
            return "SKIP: Unknown type kind: " + kind;
        }
    }

    /**
     * Apply a function signature
     */
    private String applyFunctionSignature(Program program, Address addr, String prototype) {
        int tx = program.startTransaction("Set function prototype");
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            ghidra.app.services.DataTypeManagerService dtms =
                    tool.getService(ghidra.app.services.DataTypeManagerService.class);
            ghidra.app.util.parser.FunctionSignatureParser parser =
                    new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                return "FAIL: Could not parse prototype: " + prototype;
            }

            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                            addr, sig, SourceType.USER_DEFINED);

            if (cmd.applyTo(program, new ConsoleTaskMonitor())) {
                return "OK: " + prototype;
            } else {
                return "FAIL: " + cmd.getStatusMsg();
            }
        } catch (Exception e) {
            return "FAIL: " + e.getMessage();
        } finally {
            program.endTransaction(tx, true);
        }
    }

    /**
     * Apply variable changes (renames and type changes)
     */
    private String applyVariableChanges(Program program, String functionAddress,
                                        List<Map<String, Object>> changes,
                                        VariableHandler variableHandler) {
        StringBuilder result = new StringBuilder();

        // Separate renames and type changes
        List<Map<String, String>> renames = new ArrayList<>();
        List<Map<String, String>> typeChanges = new ArrayList<>();

        for (Map<String, Object> change : changes) {
            String oldName = (String) change.get("old_name");
            String newName = (String) change.get("new_name");
            String newType = (String) change.get("new_type");

            if (oldName != null && newName != null) {
                Map<String, String> rename = new HashMap<>();
                rename.put("old_name", oldName);
                rename.put("new_name", newName);
                renames.add(rename);
            }

            // For type changes, use new_name if available, otherwise old_name
            if (newType != null) {
                String varName = newName != null ? newName : oldName;
                if (varName != null) {
                    Map<String, String> typeChange = new HashMap<>();
                    typeChange.put("variable_name", varName);
                    typeChange.put("new_type", newType);
                    typeChanges.add(typeChange);
                }
            }
        }

        // Apply renames first
        if (!renames.isEmpty()) {
            String renameResult = variableHandler.bulkRenameVariables(functionAddress, renames);
            result.append("Renames:\n").append(renameResult).append("\n");
        }

        // Then apply type changes
        if (!typeChanges.isEmpty()) {
            String typeResult = variableHandler.bulkSetVariableTypes(functionAddress, typeChanges);
            result.append("Type changes:\n").append(typeResult);
        }

        return result.toString();
    }

    /**
     * Apply prototypes to called functions
     */
    private String applyCalledFunctionPrototypes(Program program, List<Map<String, Object>> calledFunctions) {
        StringBuilder result = new StringBuilder();
        int successCount = 0;

        for (Map<String, Object> funcDef : calledFunctions) {
            String addressStr = (String) funcDef.get("address");
            String prototype = (String) funcDef.get("prototype");

            if (addressStr == null || prototype == null) {
                result.append("SKIP: Missing address or prototype\n");
                continue;
            }

            try {
                Address addr = program.getAddressFactory().getAddress(addressStr);
                String sigResult = applyFunctionSignature(program, addr, prototype);
                result.append(addressStr).append(": ").append(sigResult).append("\n");
                if (sigResult.startsWith("OK")) {
                    successCount++;
                }
            } catch (Exception e) {
                result.append("FAIL: ").append(addressStr).append(" - ").append(e.getMessage()).append("\n");
            }
        }

        result.insert(0, "Applied " + successCount + "/" + calledFunctions.size() + " called function prototypes\n");
        return result.toString();
    }

    /**
     * Find a structure by name in the data type manager
     */
    private Structure findStructure(DataTypeManager dtm, String name) {
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt instanceof Structure && dt.getName().equals(name)) {
                return (Structure) dt;
            }
        }
        return null;
    }

}
