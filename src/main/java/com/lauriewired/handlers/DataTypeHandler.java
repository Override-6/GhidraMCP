package com.lauriewired.handlers;

import com.lauriewired.util.DataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Handler for data type operations including structure field manipulation
 * and creating new data types.
 */
public class DataTypeHandler {

    private final ProgramProvider programProvider;

    public DataTypeHandler(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    /**
     * Rename a field within a structure.
     *
     * @param structureName The name of the structure
     * @param oldFieldName The current field name
     * @param newFieldName The new field name
     * @return Result message
     */
    public String renameStructureField(String structureName, String oldFieldName, String newFieldName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        if (oldFieldName == null || oldFieldName.isEmpty()) return "Old field name is required";
        if (newFieldName == null || newFieldName.isEmpty()) return "New field name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to rename field");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename structure field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Structure struct = findStructure(dtm, structureName);

                    if (struct == null) {
                        result.set("Structure not found: " + structureName);
                        return;
                    }

                    DataTypeComponent component = findComponentByName(struct, oldFieldName);
                    if (component == null) {
                        result.set("Field not found: " + oldFieldName + " in structure " + structureName);
                        return;
                    }

                    // Get the component index for modification
                    int ordinal = component.getOrdinal();
                    try {
                        struct.getComponent(ordinal).setFieldName(newFieldName);
                        result.set("Field renamed successfully: " + oldFieldName + " -> " + newFieldName);
                    } catch (Exception e) {
                        result.set("Error renaming field: " + e.getMessage());
                    }
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Field renamed"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to rename structure field on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Retype a field within a structure.
     *
     * @param structureName The name of the structure
     * @param fieldName The field name to retype
     * @param newTypeName The new type name
     * @return Result message
     */
    public String retypeStructureField(String structureName, String fieldName, String newTypeName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";
        if (newTypeName == null || newTypeName.isEmpty()) return "New type name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to retype field");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Retype structure field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Structure struct = findStructure(dtm, structureName);

                    if (struct == null) {
                        result.set("Structure not found: " + structureName);
                        return;
                    }

                    DataTypeComponent component = findComponentByName(struct, fieldName);
                    if (component == null) {
                        result.set("Field not found: " + fieldName + " in structure " + structureName);
                        return;
                    }

                    DataType newType = DataTypeUtils.resolveDataType(dtm, newTypeName);
                    if (newType == null) {
                        result.set("Could not resolve data type: " + newTypeName);
                        return;
                    }

                    int ordinal = component.getOrdinal();
                    int offset = component.getOffset();
                    String currentFieldName = component.getFieldName();
                    String comment = component.getComment();

                    try {
                        // Replace the component with the new type
                        int newSize = newType.getLength();
                        struct.replaceAtOffset(offset, newType, newSize,
                                currentFieldName, comment);
                        result.set("Field retyped successfully: " + fieldName + " -> " + newTypeName +
                                " (size: " + newSize + " bytes)");
                    } catch (Exception e) {
                        result.set("Error retyping field: " + e.getMessage());
                    }
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Field retyped"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to retype structure field on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Bulk rename structure fields.
     *
     * @param structureName The name of the structure
     * @param renames List of {oldName, newName} pairs as JSON-like format
     * @return Result message with success/failure for each rename
     */
    public String bulkRenameStructureFields(String structureName, List<Map<String, String>> renames) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        if (renames == null || renames.isEmpty()) return "Rename list is required";

        AtomicReference<String> result = new AtomicReference<>();
        StringBuilder sb = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Bulk rename structure fields");
                int successCount = 0;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Structure struct = findStructure(dtm, structureName);

                    if (struct == null) {
                        sb.append("Structure not found: ").append(structureName);
                        return;
                    }

                    for (Map<String, String> rename : renames) {
                        String oldName = rename.get("old_name");
                        String newName = rename.get("new_name");

                        if (oldName == null || newName == null) {
                            sb.append("SKIP: Invalid rename entry (missing old_name or new_name)\n");
                            continue;
                        }

                        DataTypeComponent component = findComponentByName(struct, oldName);
                        if (component == null) {
                            sb.append("FAIL: Field not found: ").append(oldName).append("\n");
                            continue;
                        }

                        try {
                            struct.getComponent(component.getOrdinal()).setFieldName(newName);
                            sb.append("OK: ").append(oldName).append(" -> ").append(newName).append("\n");
                            successCount++;
                        } catch (Exception e) {
                            sb.append("FAIL: ").append(oldName).append(" - ").append(e.getMessage()).append("\n");
                        }
                    }

                    sb.insert(0, "Bulk rename completed. Success: " + successCount + "/" + renames.size() + "\n");
                } finally {
                    program.endTransaction(tx, true);
                }
                result.set(sb.toString());
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to bulk rename structure fields on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Bulk retype structure fields.
     *
     * @param structureName The name of the structure
     * @param retypes List of {fieldName, newType} pairs
     * @return Result message with success/failure for each retype
     */
    public String bulkRetypeStructureFields(String structureName, List<Map<String, String>> retypes) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        if (retypes == null || retypes.isEmpty()) return "Retype list is required";

        AtomicReference<String> result = new AtomicReference<>();
        StringBuilder sb = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Bulk retype structure fields");
                int successCount = 0;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Structure struct = findStructure(dtm, structureName);

                    if (struct == null) {
                        sb.append("Structure not found: ").append(structureName);
                        return;
                    }

                    for (Map<String, String> retype : retypes) {
                        String fieldName = retype.get("field_name");
                        String newTypeName = retype.get("new_type");

                        if (fieldName == null || newTypeName == null) {
                            sb.append("SKIP: Invalid retype entry (missing field_name or new_type)\n");
                            continue;
                        }

                        DataTypeComponent component = findComponentByName(struct, fieldName);
                        if (component == null) {
                            sb.append("FAIL: Field not found: ").append(fieldName).append("\n");
                            continue;
                        }

                        DataType newType = DataTypeUtils.resolveDataType(dtm, newTypeName);
                        if (newType == null) {
                            sb.append("FAIL: Could not resolve type: ").append(newTypeName).append("\n");
                            continue;
                        }

                        try {
                            int offset = component.getOffset();
                            String currentFieldName = component.getFieldName();
                            String comment = component.getComment();
                            int newSize = newType.getLength();
                            struct.replaceAtOffset(offset, newType, newSize, currentFieldName, comment);
                            sb.append("OK: ").append(fieldName).append(" -> ").append(newTypeName)
                                    .append(" (").append(newSize).append(" bytes)\n");
                            successCount++;
                        } catch (Exception e) {
                            sb.append("FAIL: ").append(fieldName).append(" - ").append(e.getMessage()).append("\n");
                        }
                    }

                    sb.insert(0, "Bulk retype completed. Success: " + successCount + "/" + retypes.size() + "\n");
                } finally {
                    program.endTransaction(tx, true);
                }
                result.set(sb.toString());
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to bulk retype structure fields on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Create a new structure data type.
     *
     * @param name Structure name
     * @param categoryPath Category path (e.g., "/MyTypes")
     * @param size Initial size (0 for auto-size)
     * @return Result message
     */
    public String createStructure(String name, String categoryPath, int size) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Structure name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create structure");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create structure");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Check if structure already exists
                    Structure existing = findStructure(dtm, name);
                    if (existing != null) {
                        result.set("Structure already exists: " + existing.getPathName() +
                                ". Use existing structure or choose a different name.");
                        return;
                    }

                    // Create category if specified
                    CategoryPath catPath = categoryPath != null && !categoryPath.isEmpty()
                            ? new CategoryPath(categoryPath)
                            : CategoryPath.ROOT;

                    // Create the structure
                    StructureDataType newStruct = new StructureDataType(catPath, name, size, dtm);
                    DataType addedType = dtm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);

                    result.set("Structure created: " + addedType.getPathName());
                } catch (Exception e) {
                    result.set("Error creating structure: " + e.getMessage());
                    Msg.error(this, "Error creating structure", e);
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Structure created"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to create structure on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Create a new structure data type with fields.
     *
     * @param name Structure name
     * @param categoryPath Category path (e.g., "/MyTypes")
     * @param size Initial size (0 for auto-size)
     * @param fields List of field definitions, each with "name", "type", and optionally "offset"
     * @return Result message
     */
    public String createStructureWithFields(String name, String categoryPath, int size,
            List<Map<String, String>> fields) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Structure name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create structure");
        StringBuilder sb = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create structure with fields");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Check if structure already exists
                    Structure existing = findStructure(dtm, name);
                    if (existing != null) {
                        result.set("Structure already exists: " + existing.getPathName() +
                                ". Use existing structure or choose a different name.");
                        return;
                    }

                    // Create category if specified
                    CategoryPath catPath = categoryPath != null && !categoryPath.isEmpty()
                            ? new CategoryPath(categoryPath)
                            : CategoryPath.ROOT;

                    // Create the structure
                    StructureDataType newStruct = new StructureDataType(catPath, name, size, dtm);

                    // Add fields if provided
                    int fieldSuccessCount = 0;
                    if (fields != null && !fields.isEmpty()) {
                        for (Map<String, String> field : fields) {
                            String fieldName = field.get("name");
                            String fieldTypeName = field.get("type");
                            String offsetStr = field.get("offset");

                            if (fieldTypeName == null || fieldTypeName.isEmpty()) {
                                sb.append("SKIP: Missing type for field ").append(fieldName).append("\n");
                                continue;
                            }

                            DataType fieldType = DataTypeUtils.resolveDataType(dtm, fieldTypeName);
                            if (fieldType == null) {
                                sb.append("SKIP: Could not resolve type '").append(fieldTypeName)
                                        .append("' for field ").append(fieldName).append("\n");
                                continue;
                            }

                            try {
                                int fieldSize = fieldType.getLength();
                                if (offsetStr != null && !offsetStr.isEmpty()) {
                                    int offset = Integer.parseInt(offsetStr);
                                    newStruct.insertAtOffset(offset, fieldType, fieldSize, fieldName, null);
                                } else {
                                    newStruct.add(fieldType, fieldSize, fieldName, null);
                                }
                                sb.append("OK: ").append(fieldName).append(" (").append(fieldTypeName)
                                        .append(", ").append(fieldSize).append(" bytes)\n");
                                fieldSuccessCount++;
                            } catch (Exception e) {
                                sb.append("FAIL: ").append(fieldName).append(" - ").append(e.getMessage()).append("\n");
                            }
                        }
                    }

                    DataType addedType = dtm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);

                    // Get final structure to report size
                    Structure finalStruct = (Structure) addedType;
                    sb.insert(0, "Structure created: " + addedType.getPathName() +
                            " (size: " + finalStruct.getLength() + " bytes)\n" +
                            "Fields added: " + fieldSuccessCount + "/" +
                            (fields != null ? fields.size() : 0) + "\n");
                    result.set(sb.toString());
                } catch (Exception e) {
                    result.set("Error creating structure: " + e.getMessage());
                    Msg.error(this, "Error creating structure", e);
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Structure created"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to create structure on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Add multiple fields to an existing structure in a single operation.
     *
     * @param structureName The structure to modify
     * @param fields List of field definitions, each with "name", "type", and optionally "offset"
     * @return Result message with success/failure for each field
     */
    public String bulkAddStructureFields(String structureName, List<Map<String, String>> fields) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        if (fields == null || fields.isEmpty()) return "Fields list is required";

        AtomicReference<String> result = new AtomicReference<>();
        StringBuilder sb = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Bulk add structure fields");
                int successCount = 0;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Structure struct = findStructure(dtm, structureName);

                    if (struct == null) {
                        sb.append("Structure not found: ").append(structureName);
                        result.set(sb.toString());
                        return;
                    }

                    for (Map<String, String> field : fields) {
                        String fieldName = field.get("name");
                        String fieldTypeName = field.get("type");
                        String offsetStr = field.get("offset");

                        if (fieldTypeName == null || fieldTypeName.isEmpty()) {
                            sb.append("SKIP: Missing type for field ").append(fieldName).append("\n");
                            continue;
                        }

                        DataType fieldType = DataTypeUtils.resolveDataType(dtm, fieldTypeName);
                        if (fieldType == null) {
                            sb.append("FAIL: Could not resolve type '").append(fieldTypeName)
                                    .append("' for field ").append(fieldName).append("\n");
                            continue;
                        }

                        try {
                            int fieldSize = fieldType.getLength();
                            if (offsetStr != null && !offsetStr.isEmpty()) {
                                int offset = Integer.parseInt(offsetStr);
                                struct.insertAtOffset(offset, fieldType, fieldSize, fieldName, null);
                                sb.append("OK: +0x").append(Integer.toHexString(offset)).append(": ")
                                        .append(fieldName).append(" (").append(fieldTypeName)
                                        .append(", ").append(fieldSize).append(" bytes)\n");
                            } else {
                                struct.add(fieldType, fieldSize, fieldName, null);
                                sb.append("OK: ").append(fieldName).append(" (").append(fieldTypeName)
                                        .append(", ").append(fieldSize).append(" bytes)\n");
                            }
                            successCount++;
                        } catch (Exception e) {
                            sb.append("FAIL: ").append(fieldName).append(" - ").append(e.getMessage()).append("\n");
                        }
                    }

                    sb.insert(0, "Bulk add fields to " + structureName + " completed. Success: " +
                            successCount + "/" + fields.size() + "\n" +
                            "New structure size: " + struct.getLength() + " bytes\n");
                } finally {
                    program.endTransaction(tx, true);
                }
                result.set(sb.toString());
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to bulk add structure fields on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Create a new enum data type.
     *
     * @param name Enum name
     * @param categoryPath Category path (e.g., "/MyTypes")
     * @param size Size in bytes (1, 2, 4, or 8)
     * @return Result message
     */
    public String createEnum(String name, String categoryPath, int size) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Enum name is required";
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return "Enum size must be 1, 2, 4, or 8 bytes";
        }

        AtomicReference<String> result = new AtomicReference<>("Failed to create enum");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Check if enum already exists
                    DataType existing = DataTypeUtils.findDataTypeByNameInAllCategories(dtm, name);
                    if (existing instanceof ghidra.program.model.data.Enum) {
                        result.set("Enum already exists: " + existing.getPathName() +
                                ". Use existing enum or choose a different name.");
                        return;
                    }

                    CategoryPath catPath = categoryPath != null && !categoryPath.isEmpty()
                            ? new CategoryPath(categoryPath)
                            : CategoryPath.ROOT;

                    EnumDataType newEnum = new EnumDataType(catPath, name, size, dtm);
                    DataType addedType = dtm.addDataType(newEnum, DataTypeConflictHandler.REPLACE_HANDLER);

                    result.set("Enum created: " + addedType.getPathName());
                } catch (Exception e) {
                    result.set("Error creating enum: " + e.getMessage());
                    Msg.error(this, "Error creating enum", e);
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Enum created"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to create enum on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Create a new typedef.
     *
     * @param name Typedef name
     * @param baseTypeName The base type to alias
     * @param categoryPath Category path (e.g., "/MyTypes")
     * @return Result message
     */
    public String createTypedef(String name, String baseTypeName, String categoryPath) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Typedef name is required";
        if (baseTypeName == null || baseTypeName.isEmpty()) return "Base type name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create typedef");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create typedef");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Check if typedef already exists
                    DataType existing = DataTypeUtils.findDataTypeByNameInAllCategories(dtm, name);
                    if (existing != null) {
                        result.set("Type already exists: " + existing.getPathName() +
                                ". Use existing type or choose a different name.");
                        return;
                    }

                    // Resolve base type
                    DataType baseType = DataTypeUtils.resolveDataType(dtm, baseTypeName);
                    if (baseType == null) {
                        result.set("Could not resolve base type: " + baseTypeName);
                        return;
                    }

                    CategoryPath catPath = categoryPath != null && !categoryPath.isEmpty()
                            ? new CategoryPath(categoryPath)
                            : CategoryPath.ROOT;

                    TypedefDataType newTypedef = new TypedefDataType(catPath, name, baseType, dtm);
                    DataType addedType = dtm.addDataType(newTypedef, DataTypeConflictHandler.REPLACE_HANDLER);

                    result.set("Typedef created: " + addedType.getPathName() + " -> " + baseTypeName);
                } catch (Exception e) {
                    result.set("Error creating typedef: " + e.getMessage());
                    Msg.error(this, "Error creating typedef", e);
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Typedef created"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to create typedef on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Add a field to an existing structure.
     *
     * @param structureName The structure to modify
     * @param fieldName The new field name
     * @param fieldTypeName The field type
     * @param offset Offset in the structure (-1 to append)
     * @return Result message
     */
    public String addStructureField(String structureName, String fieldName, String fieldTypeName, int offset) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        if (fieldTypeName == null || fieldTypeName.isEmpty()) return "Field type is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to add field");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add structure field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Structure struct = findStructure(dtm, structureName);

                    if (struct == null) {
                        result.set("Structure not found: " + structureName);
                        return;
                    }

                    DataType fieldType = DataTypeUtils.resolveDataType(dtm, fieldTypeName);
                    if (fieldType == null) {
                        result.set("Could not resolve field type: " + fieldTypeName);
                        return;
                    }

                    int fieldSize = fieldType.getLength();
                    if (offset < 0) {
                        // Append to end
                        struct.add(fieldType, fieldSize, fieldName, null);
                    } else {
                        // Insert at specific offset
                        struct.insertAtOffset(offset, fieldType, fieldSize, fieldName, null);
                    }

                    result.set("Field added: " + fieldName + " (" + fieldTypeName + ", size: " +
                            fieldSize + " bytes) to " + structureName);
                } catch (Exception e) {
                    result.set("Error adding field: " + e.getMessage());
                    Msg.error(this, "Error adding field", e);
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Field added"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to add structure field on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Add a value to an existing enum.
     *
     * @param enumName The enum to modify
     * @param valueName The new value name
     * @param value The numeric value
     * @return Result message
     */
    public String addEnumValue(String enumName, String valueName, long value) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || enumName.isEmpty()) return "Enum name is required";
        if (valueName == null || valueName.isEmpty()) return "Value name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to add enum value");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add enum value");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = DataTypeUtils.findDataTypeByNameInAllCategories(dtm, enumName);

                    if (!(dt instanceof ghidra.program.model.data.Enum)) {
                        result.set("Enum not found: " + enumName);
                        return;
                    }

                    ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
                    enumType.add(valueName, value);

                    result.set("Value added: " + valueName + " = " + value + " to " + enumName);
                } catch (Exception e) {
                    result.set("Error adding enum value: " + e.getMessage());
                    Msg.error(this, "Error adding enum value", e);
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Value added"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to add enum value on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Resize a structure to a specific size.
     *
     * @param structureName The name of the structure
     * @param newSize The new size in bytes
     * @return Result message
     */
    public String resizeStructure(String structureName, int newSize) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        if (newSize <= 0) return "New size must be positive";

        AtomicReference<String> result = new AtomicReference<>("Failed to resize structure");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Resize structure");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Structure struct = findStructure(dtm, structureName);

                    if (struct == null) {
                        result.set("Structure not found: " + structureName);
                        return;
                    }

                    int currentSize = struct.getLength();

                    if (newSize == currentSize) {
                        result.set("Structure already has size " + newSize);
                        return;
                    }

                    if (newSize > currentSize) {
                        // Grow the structure by adding undefined bytes at the end
                        struct.growStructure(newSize - currentSize);
                        result.set("Structure resized from " + currentSize + " to " + newSize + " bytes");
                    } else {
                        // Shrink - need to delete components that extend beyond new size
                        // First, delete all components that start at or after newSize
                        for (int i = struct.getNumComponents() - 1; i >= 0; i--) {
                            DataTypeComponent comp = struct.getComponent(i);
                            if (comp.getOffset() >= newSize) {
                                struct.delete(i);
                            } else if (comp.getOffset() + comp.getLength() > newSize) {
                                // Component spans the boundary - delete it too
                                struct.delete(i);
                            }
                        }
                        // Now set explicit minimum size if needed
                        // Note: Some versions of Ghidra may not support shrinking below data
                        result.set("Structure resized from " + currentSize + " to approximately " +
                                struct.getLength() + " bytes (components extending beyond were removed)");
                    }
                } catch (Exception e) {
                    result.set("Error resizing structure: " + e.getMessage());
                    Msg.error(this, "Error resizing structure", e);
                } finally {
                    program.endTransaction(tx, result.get().contains("resized"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to resize structure on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Create a new function definition (function type).
     * Function definitions are used for function pointers in structures (e.g., vtables).
     *
     * @param name The function type name (e.g., "UpdateFunc", "VTable_Method1")
     * @param returnTypeName Return type (e.g., "void", "int", "Player*")
     * @param parameterTypes List of parameter type names (e.g., ["void*", "int", "float"])
     * @param parameterNames List of parameter names (e.g., ["this", "param1", "delta"])
     * @param categoryPath Category path (e.g., "/VTables", "/FunctionTypes")
     * @return Result message
     */
    public String createFunctionDefinition(String name, String returnTypeName,
            List<String> parameterTypes, List<String> parameterNames, String categoryPath) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Function definition name is required";
        if (returnTypeName == null || returnTypeName.isEmpty()) return "Return type is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create function definition");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function definition");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Check if already exists
                    DataType existing = DataTypeUtils.findDataTypeByNameInAllCategories(dtm, name);
                    if (existing instanceof FunctionDefinition) {
                        result.set("Function definition already exists: " + existing.getPathName() +
                                ". Use existing type or choose a different name.");
                        return;
                    }

                    // Resolve return type
                    DataType returnType = DataTypeUtils.resolveDataType(dtm, returnTypeName);
                    if (returnType == null) {
                        result.set("Could not resolve return type: " + returnTypeName);
                        return;
                    }

                    CategoryPath catPath = categoryPath != null && !categoryPath.isEmpty()
                            ? new CategoryPath(categoryPath)
                            : CategoryPath.ROOT;

                    // Create the function definition
                    FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(catPath, name, dtm);
                    funcDef.setReturnType(returnType);

                    // Add parameters
                    if (parameterTypes != null && !parameterTypes.isEmpty()) {
                        int numParams = parameterTypes.size();
                        ParameterDefinition[] params = new ParameterDefinition[numParams];

                        for (int i = 0; i < numParams; i++) {
                            String paramTypeName = parameterTypes.get(i);
                            DataType paramType = DataTypeUtils.resolveDataType(dtm, paramTypeName);

                            if (paramType == null) {
                                result.set("Could not resolve parameter type: " + paramTypeName);
                                return;
                            }

                            String paramName = (parameterNames != null && i < parameterNames.size())
                                    ? parameterNames.get(i)
                                    : "param" + (i + 1);

                            params[i] = new ParameterDefinitionImpl(paramName, paramType, null);
                        }
                        funcDef.setArguments(params);
                    }

                    // Add to data type manager
                    DataType addedType = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);

                    // Build signature string for result message
                    StringBuilder sig = new StringBuilder();
                    sig.append(returnTypeName).append(" ").append(name).append("(");
                    if (parameterTypes != null) {
                        for (int i = 0; i < parameterTypes.size(); i++) {
                            if (i > 0) sig.append(", ");
                            sig.append(parameterTypes.get(i));
                            if (parameterNames != null && i < parameterNames.size()) {
                                sig.append(" ").append(parameterNames.get(i));
                            }
                        }
                    }
                    sig.append(")");

                    result.set("Function definition created: " + addedType.getPathName() + "\n" +
                            "Signature: " + sig.toString());
                } catch (Exception e) {
                    result.set("Error creating function definition: " + e.getMessage());
                    Msg.error(this, "Error creating function definition", e);
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Function definition created"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to create function definition on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Create a function definition from a C-style prototype string.
     * This parses a prototype like "void* (*UpdateFunc)(Player* this, float delta)"
     *
     * @param prototype The function prototype string
     * @param categoryPath Category path (e.g., "/VTables")
     * @return Result message
     */
    public String createFunctionDefinitionFromPrototype(String prototype, String categoryPath) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (prototype == null || prototype.isEmpty()) return "Prototype is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create function definition");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function definition from prototype");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    ghidra.app.services.DataTypeManagerService dtms = null;
                    // Note: We don't have tool reference here, so we'll use parser without dtms

                    ghidra.app.util.parser.FunctionSignatureParser parser =
                            new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

                    FunctionDefinitionDataType funcDef = parser.parse(null, prototype);

                    if (funcDef == null) {
                        result.set("Failed to parse prototype: " + prototype);
                        return;
                    }

                    // Check if already exists
                    DataType existing = DataTypeUtils.findDataTypeByNameInAllCategories(dtm, funcDef.getName());
                    if (existing instanceof FunctionDefinition) {
                        result.set("Function definition already exists: " + existing.getPathName() +
                                ". Use existing type or choose a different name.");
                        return;
                    }

                    // Set category if specified
                    if (categoryPath != null && !categoryPath.isEmpty()) {
                        CategoryPath catPath = new CategoryPath(categoryPath);
                        funcDef.setCategoryPath(catPath);
                    }

                    // Add to data type manager
                    DataType addedType = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);

                    result.set("Function definition created: " + addedType.getPathName() + "\n" +
                            "Prototype: " + funcDef.getPrototypeString());
                } catch (ghidra.util.exception.CancelledException e) {
                    result.set("Operation cancelled");
                } catch (Exception e) {
                    result.set("Error creating function definition: " + e.getMessage());
                    Msg.error(this, "Error creating function definition", e);
                } finally {
                    program.endTransaction(tx, result.get().startsWith("Function definition created"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to create function definition on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

    // ============ Helper Methods ============

    /**
     * Find a structure by name in the data type manager.
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

    /**
     * Find a component in a structure by field name.
     */
    private DataTypeComponent findComponentByName(Structure struct, String fieldName) {
        for (DataTypeComponent component : struct.getComponents()) {
            String name = component.getFieldName();
            if (name != null && name.equals(fieldName)) {
                return component;
            }
        }
        return null;
    }
}
