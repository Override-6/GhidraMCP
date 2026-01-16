package com.lauriewired.util;

import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.util.Msg;

import java.util.Iterator;

/**
 * Utility class for data type resolution and lookup
 */
public class DataTypeUtils {

    /**
     * Resolves a data type by name, searching Program DTM, Built-ins, and Linked Archives.
     * * @param dtm The data type manager (usually program.getDataTypeManager())
     *
     * @param typeName The type name to resolve (e.g., "double", "StringItem*", "size_t")
     * @return The resolved DataType, or null if not found
     */
    public static DataType resolveDataType(DataTypeManager dtm, String typeName, PluginTool tool) {

        if (typeName == null || typeName.isEmpty()) return null;
        typeName = typeName.trim();

        DataType result = resolveDataTypeFor(dtm, typeName, tool);
        if (result != null)
            return result;

        DataTypeManagerService dtms =
                tool.getService(DataTypeManagerService.class);

        for (DataTypeManager otherDtm : dtms.getDataTypeManagers()) {
            if (otherDtm == dtm)
                continue;


            result = resolveDataTypeFor(otherDtm, typeName, tool);
            if (result != null)
                return result;
        }

        return result;
    }

    private static DataType resolveDataTypeFor(DataTypeManager dtm, String typeName, PluginTool tool) {

        // 1. HANDLE POINTERS (Recursive)
        if (typeName.endsWith("*")) {
            int pointerDepth = 0;
            String baseTypeName = typeName;
            while (baseTypeName.endsWith("*")) {
                pointerDepth++;
                baseTypeName = baseTypeName.substring(0, baseTypeName.length() - 1).trim();
            }

            DataType baseType = resolveDataType(dtm, baseTypeName, tool);

            // If base type is unknown, default to void* rather than failing
            if (baseType == null) {
                Msg.warn(DataTypeUtils.class, "Base type '" + baseTypeName + "' not found, using void* for " + typeName);
                baseType = DataType.VOID;
            }

            DataType result = baseType;
            for (int i = 0; i < pointerDepth; i++) {
                result = new PointerDataType(result, dtm);
            }
            return result;
        }

        // We check exact matches and all categories
        DataType dt = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dt != null) return dt;

        BuiltInDataTypeManager builtins = BuiltInDataTypeManager.getDataTypeManager();

        dt = builtins.getDataType(typeName);
        if (dt != null) return dt;

        if (typeName.contains("/")) {
            dt = dtm.getDataType(typeName);
            if (dt != null) return dt;
        }

        DataTypeManagerService dtms =
                tool.getService(DataTypeManagerService.class);

        for (DataTypeManager dtmBis : dtms.getDataTypeManagers()) {
            if (dtmBis == dtm) continue;
        }

        Msg.warn(DataTypeUtils.class, "Could not resolve type: " + typeName);
        return null;
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

    /**
     * Find a structure by name in the data type manager.
     *
     * @param dtm  The data type manager
     * @param name The structure name to find
     * @return The Structure if found, null otherwise
     */
    public static Structure findStructure(DataTypeManager dtm, String name) {
        if (dtm == null || name == null || name.isEmpty()) {
            return null;
        }
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
