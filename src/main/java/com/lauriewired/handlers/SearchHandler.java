package com.lauriewired.handlers;

import com.lauriewired.util.HttpUtils;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Handler for RAG (Retrieval Augmented Generation) search operations.
 * Provides regex-based search for functions, strings, and data types.
 */
public class SearchHandler {

    private final ProgramProvider programProvider;

    public SearchHandler(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    /**
     * Search for functions by regex pattern on name and/or signature.
     * The pattern is matched against the full function signature string.
     *
     * @param regexPattern The regex pattern to match (e.g., ".*GameSession\\*.*" to find functions with GameSession* parameter)
     * @param offset       Pagination offset
     * @param limit        Maximum number of results
     * @return Matching functions with their addresses and signatures
     */
    public String searchFunctionsByRegex(String regexPattern, int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (regexPattern == null || regexPattern.isEmpty()) return "Regex pattern is required";

        Pattern pattern;
        try {
            pattern = Pattern.compile(regexPattern, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            return "Invalid regex pattern: " + e.getMessage();
        }

        List<String> matches = new ArrayList<>();
        FunctionManager funcManager = program.getFunctionManager();

        for (Function func : funcManager.getFunctions(true)) {
            String signature = func.getSignature().getPrototypeString();
            String fullName = getFullFunctionName(func);

            // Match against signature (includes return type, name, and parameters)
            Matcher sigMatcher = pattern.matcher(signature);
            // Match against full name (includes namespace)
            Matcher nameMatcher = pattern.matcher(fullName);

            if (sigMatcher.find() || nameMatcher.find()) {
                matches.add(formatFunctionResult(func));
            }
        }

        if (matches.isEmpty()) {
            return "No functions matching pattern: " + regexPattern;
        }

        return HttpUtils.paginateList(matches, offset, limit);
    }

    /**
     * Search for defined strings by regex pattern.
     *
     * @param regexPattern The regex pattern to match against string content
     * @param offset       Pagination offset
     * @param limit        Maximum number of results
     * @return Matching strings with their addresses
     */
    public String searchStringsByRegex(String regexPattern, int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (regexPattern == null || regexPattern.isEmpty()) return "Regex pattern is required";

        Pattern pattern;
        try {
            pattern = Pattern.compile(regexPattern, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            return "Invalid regex pattern: " + e.getMessage();
        }

        List<String> matches = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                Matcher matcher = pattern.matcher(value);

                if (matcher.find()) {
                    String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    matches.add(String.format("%s @ %s: \"%s\"",
                            label,
                            data.getAddress(),
                            escapeString(value)));
                }
            }
        }

        if (matches.isEmpty()) {
            return "No strings matching pattern: " + regexPattern;
        }

        return HttpUtils.paginateList(matches, offset, limit);
    }

    /**
     * Search for data types (structures, enums, typedefs) by regex pattern.
     *
     * @param regexPattern The regex pattern to match against type names
     * @param offset       Pagination offset
     * @param limit        Maximum number of results
     * @return Matching data types with their details
     */
    public String searchDataTypesByRegex(String regexPattern, int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (regexPattern == null || regexPattern.isEmpty()) return "Regex pattern is required";

        Pattern pattern;
        try {
            pattern = Pattern.compile(regexPattern, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            return "Invalid regex pattern: " + e.getMessage();
        }

        List<String> matches = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();

        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            String typeName = dt.getName();
            String pathName = dt.getPathName();

            Matcher nameMatcher = pattern.matcher(typeName);
            Matcher pathMatcher = pattern.matcher(pathName);

            if (nameMatcher.find() || pathMatcher.find()) {
                matches.add(formatDataTypeResult(dt));
            }
        }

        if (matches.isEmpty()) {
            return "No data types matching pattern: " + regexPattern;
        }

        // Sort for consistent ordering
        Collections.sort(matches);
        return HttpUtils.paginateList(matches, offset, limit);
    }

    /**
     * List all defined structures in the program.
     *
     * @param offset Pagination offset
     * @param limit  Maximum number of results
     * @return List of structures with their field information
     */
    public String listStructures(int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> structures = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();

        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt instanceof Structure) {
                structures.add(formatStructureDetails((Structure) dt));
            }
        }

        if (structures.isEmpty()) {
            return "No structures defined in program";
        }

        Collections.sort(structures);
        return HttpUtils.paginateList(structures, offset, limit);
    }

    /**
     * Get detailed information about a specific structure.
     *
     * @param structName The name of the structure
     * @return Structure details including all fields
     */
    public String getStructureDetails(String structName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();

        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt instanceof Structure && dt.getName().equals(structName)) {
                return formatStructureFullDetails((Structure) dt);
            }
        }

        return "Structure not found: " + structName;
    }

    /**
     * List all enums in the program.
     *
     * @param offset Pagination offset
     * @param limit  Maximum number of results
     * @return List of enums with their values
     */
    public String listEnums(int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> enums = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();

        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt instanceof ghidra.program.model.data.Enum) {
                enums.add(formatEnumDetails((ghidra.program.model.data.Enum) dt));
            }
        }

        if (enums.isEmpty()) {
            return "No enums defined in program";
        }

        Collections.sort(enums);
        return HttpUtils.paginateList(enums, offset, limit);
    }

    // ============ Helper Methods ============

    /**
     * Get the full name of a function including its namespace.
     */
    private String getFullFunctionName(Function func) {
        Namespace ns = func.getParentNamespace();
        if (ns != null && !ns.isGlobal()) {
            return ns.getName() + "::" + func.getName();
        }
        return func.getName();
    }

    /**
     * Format a function result with address and signature.
     */
    private String formatFunctionResult(Function func) {
        String fullName = getFullFunctionName(func);
        String signature = func.getSignature().getPrototypeString();
        return String.format("%s @ %s | %s", fullName, func.getEntryPoint(), signature);
    }

    /**
     * Format a data type result with category and details.
     */
    private String formatDataTypeResult(DataType dt) {
        String typeKind = getTypeKind(dt);
        return String.format("[%s] %s (size: %d bytes)", typeKind, dt.getPathName(), dt.getLength());
    }

    /**
     * Get a human-readable kind for a data type.
     */
    private String getTypeKind(DataType dt) {
        if (dt instanceof Structure) return "STRUCT";
        if (dt instanceof Union) return "UNION";
        if (dt instanceof ghidra.program.model.data.Enum) return "ENUM";
        if (dt instanceof TypeDef) return "TYPEDEF";
        if (dt instanceof FunctionDefinition) return "FUNCDEF";
        if (dt instanceof Pointer) return "POINTER";
        if (dt instanceof Array) return "ARRAY";
        return "OTHER";
    }

    /**
     * Format structure details with field summary.
     */
    private String formatStructureDetails(Structure struct) {
        int fieldCount = struct.getNumComponents();
        return String.format("%s (size: %d, fields: %d)",
                struct.getPathName(), struct.getLength(), fieldCount);
    }

    /**
     * Format full structure details including all fields.
     */
    private String formatStructureFullDetails(Structure struct) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Structure: %s\n", struct.getPathName()));
        sb.append(String.format("Size: %d bytes\n", struct.getLength()));
        sb.append(String.format("Alignment: %d\n", struct.getAlignment()));
        sb.append("Fields:\n");

        DataTypeComponent last_component = null;
        int same_field_accumulation = 0;

        for (DataTypeComponent component : struct.getComponents()) {
            String fieldName = component.getFieldName() != null ? component.getFieldName() : "(unnamed)";
            if (last_component != null && component.getFieldName() == null && last_component.getFieldName() == null) {
                same_field_accumulation++;
                last_component = component;
                continue;
            }
            if (same_field_accumulation != 0) {
                sb.append("  <same field as above ")
                        .append(same_field_accumulation - 1)
                        .append(" times>\n");
                same_field_accumulation = 0;
                continue;
            }
            sb.append(String.format("  +0x%X: %s %s (size: %d)\n",
                    component.getOffset(),
                    component.getDataType().getName(),
                    fieldName,
                    component.getLength()));
            last_component = component;
        }

        return sb.toString();
    }

    /**
     * Format enum details with values.
     */
    private String formatEnumDetails(ghidra.program.model.data.Enum enumType) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%s (values: %d)", enumType.getPathName(), enumType.getCount()));
        return sb.toString();
    }

    /**
     * Check if the given data is a string type.
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string.
     */
    private String escapeString(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
