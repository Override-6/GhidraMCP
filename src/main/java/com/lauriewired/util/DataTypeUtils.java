package com.lauriewired.util;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.util.Msg;

import java.util.Iterator;

/**
 * Utility class for data type resolution and lookup
 */
public class DataTypeUtils {

    /**
     * Resolves a data type by name, handling common types and pointer types.
     * Pointer types will use the correct size based on the program's architecture
     * (8 bytes for 64-bit, 4 bytes for 32-bit).
     *
     * @param dtm The data type manager
     * @param typeName The type name to resolve (e.g., "int", "void*", "MyStruct*", "PVOID")
     * @return The resolved DataType, or null if not found
     */
    public static DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (typeName == null || typeName.isEmpty()) {
            return null;
        }

        // Trim whitespace
        typeName = typeName.trim();

        // Handle C-style pointer types (e.g., "void*", "MyStruct *", "int**")
        if (typeName.endsWith("*")) {
            // Count pointer depth and get base type
            int pointerDepth = 0;
            String baseTypeName = typeName;
            while (baseTypeName.endsWith("*")) {
                pointerDepth++;
                baseTypeName = baseTypeName.substring(0, baseTypeName.length() - 1).trim();
            }

            // Resolve the base type
            DataType baseType;
            if (baseTypeName.isEmpty() || baseTypeName.equalsIgnoreCase("void")) {
                baseType = dtm.getDataType("/void");
            } else {
                baseType = resolveDataType(dtm, baseTypeName);
            }

            if (baseType == null) {
                Msg.warn(DataTypeUtils.class, "Base type not found for pointer: " + baseTypeName + ", using void");
                baseType = dtm.getDataType("/void");
            }

            // Wrap in pointer types (using dtm for correct pointer size based on architecture)
            DataType result = baseType;
            for (int i = 0; i < pointerDepth; i++) {
                result = new PointerDataType(result, dtm);
            }

            Msg.info(DataTypeUtils.class, "Resolved pointer type: " + typeName + " -> " +
                    result.getDisplayName() + " (size: " + result.getLength() + " bytes)");
            return result;
        }

        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(DataTypeUtils.class, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1 && Character.isUpperCase(typeName.charAt(1))) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"), dtm);
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType, dtm);
            }

            Msg.warn(DataTypeUtils.class, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"), dtm);
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
                return dtm.getDataType("/int");
            case "long":
                // In C, 'long' can vary by platform. Use longlong for 64-bit compatibility
                DataType longType = dtm.getDataType("/long");
                if (longType != null) {
                    return longType;
                }
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "dword":
                return dtm.getDataType("/uint");
            case "ulong":
            case "unsigned long":
                DataType ulongType = dtm.getDataType("/ulong");
                if (ulongType != null) {
                    return ulongType;
                }
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "long long":
            case "__int64":
            case "int64":
            case "qword":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned long long":
            case "unsigned __int64":
            case "uint64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "float":
                return dtm.getDataType("/float");
            case "double":
                return dtm.getDataType("/double");
            case "void":
                return dtm.getDataType("/void");
            case "size_t":
            case "uintptr_t":
            case "intptr_t":
                // These should be pointer-sized - use the architecture's natural size
                int pointerSize = dtm.getDataOrganization().getPointerSize();
                if (pointerSize == 8) {
                    return dtm.getDataType("/ulonglong");
                } else {
                    return dtm.getDataType("/uint");
                }
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(DataTypeUtils.class, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    public static DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private static DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive)
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }
}
