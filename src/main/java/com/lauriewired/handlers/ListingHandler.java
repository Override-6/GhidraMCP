package com.lauriewired.handlers;

import com.lauriewired.util.HttpUtils;
import com.lauriewired.util.StringUtils;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.util.*;

/**
 * Handler for listing program elements (functions, classes, segments, imports, exports, etc.)
 */
public class ListingHandler {

    private final ProgramProvider programProvider;

    public ListingHandler(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    /**
     * Get all function names with pagination
     */
    public String getAllFunctionNames(int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return HttpUtils.paginateList(names, offset, limit);
    }

    /**
     * Get all class names with pagination
     */
    public String getAllClassNames(int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return HttpUtils.paginateList(sorted, offset, limit);
    }

    /**
     * List all memory segments with pagination
     */
    public String listSegments(int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return HttpUtils.paginateList(lines, offset, limit);
    }

    /**
     * List all imports with pagination
     */
    public String listImports(int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return HttpUtils.paginateList(lines, offset, limit);
    }

    /**
     * List all exports with pagination
     */
    public String listExports(int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return HttpUtils.paginateList(lines, offset, limit);
    }

    /**
     * List all namespaces with pagination
     */
    public String listNamespaces(int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return HttpUtils.paginateList(sorted, offset, limit);
    }

    /**
     * List all defined data with pagination
     */
    public String listDefinedData(int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                            data.getAddress(),
                            StringUtils.escapeNonAscii(label),
                            StringUtils.escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return HttpUtils.paginateList(lines, offset, limit);
    }

    /**
     * List all functions (non-paginated)
     */
    public String listFunctions() {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n",
                    func.getName(),
                    func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * List all defined strings with pagination and optional filter
     */
    public String listDefinedStrings(int offset, int limit, String filter) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = StringUtils.escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }

        return HttpUtils.paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;

        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

}
