package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpServer;

import com.lauriewired.handlers.*;
import com.lauriewired.model.PrototypeResult;
import com.lauriewired.util.DataTypeUtils;
import com.lauriewired.util.HttpUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8081;

    // Handlers
    private ListingHandler listingHandler;
    private FunctionHandler functionHandler;
    private VariableHandler variableHandler;
    private ReferenceHandler referenceHandler;
    private CommentHandler commentHandler;
    private SearchHandler searchHandler;
    private DataTypeHandler dataTypeHandler;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Initialize handlers
        initializeHandlers();

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null,
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        } catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void initializeHandlers() {
        // Create a shared program provider
        ProgramProvider programProvider = this::getCurrentProgram;

        listingHandler = new ListingHandler(programProvider);
        functionHandler = new FunctionHandler(programProvider, tool);
        variableHandler = new VariableHandler(programProvider);
        referenceHandler = new ReferenceHandler(programProvider);
        commentHandler = new CommentHandler(programProvider);
        searchHandler = new SearchHandler(programProvider);
        dataTypeHandler = new DataTypeHandler(programProvider);
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Register all endpoints
        registerListingEndpoints();
        registerFunctionEndpoints();
        registerVariableEndpoints();
        registerReferenceEndpoints();
        registerCommentEndpoints();
        registerSearchEndpoints();
        registerDataTypeEndpoints();
        registerBulkEndpoints();

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null;
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    private void registerListingEndpoints() {
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, listingHandler.getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, listingHandler.getAllClassNames(offset, limit));
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, listingHandler.listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, listingHandler.listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, listingHandler.listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, listingHandler.listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, listingHandler.listDefinedData(offset, limit));
        });

        server.createContext("/list_functions", exchange -> {
            HttpUtils.sendResponse(exchange, listingHandler.listFunctions());
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            HttpUtils.sendResponse(exchange, listingHandler.listDefinedStrings(offset, limit, filter));
        });

        server.createContext("/get_binary_info", exchange -> {
            HttpUtils.sendResponse(exchange, listingHandler.getBinaryInfo());
        });
    }

    private void registerFunctionEndpoints() {
        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            HttpUtils.sendResponse(exchange, functionHandler.decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String response = functionHandler.renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            HttpUtils.sendResponse(exchange, response);
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, functionHandler.searchFunctionsByName(searchTerm, offset, limit));
        });

        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionHandler.getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            HttpUtils.sendResponse(exchange, functionHandler.getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            HttpUtils.sendResponse(exchange, functionHandler.getCurrentFunction());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionHandler.decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionHandler.disassembleFunction(address));
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = functionHandler.renameFunctionByAddress(functionAddress, newName);
            HttpUtils.sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            PrototypeResult result = functionHandler.setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                HttpUtils.sendResponse(exchange, successMsg);
            } else {
                HttpUtils.sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });
    }

    private void registerVariableEndpoints() {
        server.createContext("/renameData", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            variableHandler.renameDataAtAddress(params.get("address"), params.get("newName"));
            HttpUtils.sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = variableHandler.renameVariableInFunction(functionName, oldName, newName);
            HttpUtils.sendResponse(exchange, result);
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                    .append(" to ").append(newType)
                    .append(" in function at ").append(functionAddress).append("\n\n");

            Program program = getCurrentProgram();
            if (program != null) {
                ghidra.program.model.data.DataTypeManager dtm = program.getDataTypeManager();
                ghidra.program.model.data.DataType directType = DataTypeUtils.findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    ghidra.program.model.data.DataType baseType = DataTypeUtils.findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            boolean success = variableHandler.setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            HttpUtils.sendResponse(exchange, responseMsg.toString());
        });
    }

    private void registerReferenceEndpoints() {
        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, referenceHandler.getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, referenceHandler.getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, referenceHandler.getFunctionXrefs(name, offset, limit));
        });
    }

    private void registerCommentEndpoints() {
        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = commentHandler.setDecompilerComment(address, comment);
            HttpUtils.sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = commentHandler.setDisassemblyComment(address, comment);
            HttpUtils.sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });
    }

    private void registerSearchEndpoints() {
        // Search functions by regex pattern (RAG for functions)
        server.createContext("/search_functions_by_regex", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, searchHandler.searchFunctionsByRegex(pattern, offset, limit));
        });

        // Search strings by regex pattern (RAG for strings)
        server.createContext("/search_strings_by_regex", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, searchHandler.searchStringsByRegex(pattern, offset, limit));
        });

        // Search data types by regex pattern (RAG for data types)
        server.createContext("/search_data_types_by_regex", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, searchHandler.searchDataTypesByRegex(pattern, offset, limit));
        });

        // List all structures
        server.createContext("/list_structures", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, searchHandler.listStructures(offset, limit));
        });

        // Get structure details
        server.createContext("/get_structure", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String name = qparams.get("name");
            HttpUtils.sendResponse(exchange, searchHandler.getStructureDetails(name));
        });

        // List all enums
        server.createContext("/list_enums", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, searchHandler.listEnums(offset, limit));
        });
    }

    private void registerDataTypeEndpoints() {
        // Rename structure field
        server.createContext("/rename_structure_field", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            String oldFieldName = params.get("old_field_name");
            String newFieldName = params.get("new_field_name");
            HttpUtils.sendResponse(exchange, dataTypeHandler.renameStructureField(structName, oldFieldName, newFieldName));
        });

        // Retype structure field
        server.createContext("/retype_structure_field", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            String fieldName = params.get("field_name");
            String newType = params.get("new_type");
            HttpUtils.sendResponse(exchange, dataTypeHandler.retypeStructureField(structName, fieldName, newType));
        });

        // Create new structure
        server.createContext("/create_structure", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String name = params.get("name");
            String categoryPath = params.get("category_path");
            int size = HttpUtils.parseIntOrDefault(params.get("size"), 0);
            HttpUtils.sendResponse(exchange, dataTypeHandler.createStructure(name, categoryPath, size));
        });

        // Create new structure with fields
        server.createContext("/create_structure_with_fields", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String name = params.get("name");
            String categoryPath = params.get("category_path");
            int size = HttpUtils.parseIntOrDefault(params.get("size"), 0);
            String fieldsJson = params.get("fields");
            List<Map<String, String>> fields = parseJsonArray(fieldsJson);
            HttpUtils.sendResponse(exchange, dataTypeHandler.createStructureWithFields(name, categoryPath, size, fields));
        });

        // Bulk add structure fields
        server.createContext("/bulk_add_structure_fields", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            String fieldsJson = params.get("fields");
            List<Map<String, String>> fields = parseJsonArray(fieldsJson);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkAddStructureFields(structName, fields));
        });

        // Create new enum
        server.createContext("/create_enum", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String name = params.get("name");
            String categoryPath = params.get("category_path");
            int size = HttpUtils.parseIntOrDefault(params.get("size"), 4);
            HttpUtils.sendResponse(exchange, dataTypeHandler.createEnum(name, categoryPath, size));
        });

        // Create new typedef
        server.createContext("/create_typedef", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String name = params.get("name");
            String baseType = params.get("base_type");
            String categoryPath = params.get("category_path");
            HttpUtils.sendResponse(exchange, dataTypeHandler.createTypedef(name, baseType, categoryPath));
        });

        // Add structure field
        server.createContext("/add_structure_field", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            String fieldName = params.get("field_name");
            String fieldType = params.get("field_type");
            int offset = HttpUtils.parseIntOrDefault(params.get("offset"), -1);
            HttpUtils.sendResponse(exchange, dataTypeHandler.addStructureField(structName, fieldName, fieldType, offset));
        });

        // Add enum value
        server.createContext("/add_enum_value", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String enumName = params.get("enum_name");
            String valueName = params.get("value_name");
            long value = Long.parseLong(params.getOrDefault("value", "0"));
            HttpUtils.sendResponse(exchange, dataTypeHandler.addEnumValue(enumName, valueName, value));
        });

        // Resize structure
        server.createContext("/resize_structure", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            int newSize = HttpUtils.parseIntOrDefault(params.get("new_size"), 0);
            HttpUtils.sendResponse(exchange, dataTypeHandler.resizeStructure(structName, newSize));
        });

        // Create function definition
        server.createContext("/create_function_definition", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String name = params.get("name");
            String returnType = params.get("return_type");
            String categoryPath = params.get("category_path");
            String paramTypesJson = params.get("parameter_types");
            String paramNamesJson = params.get("parameter_names");

            List<String> paramTypes = parseJsonStringArray(paramTypesJson);
            List<String> paramNames = parseJsonStringArray(paramNamesJson);

            HttpUtils.sendResponse(exchange, dataTypeHandler.createFunctionDefinition(
                    name, returnType, paramTypes, paramNames, categoryPath));
        });

        // Create function definition from prototype
        server.createContext("/create_function_definition_from_prototype", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String prototype = params.get("prototype");
            String categoryPath = params.get("category_path");
            HttpUtils.sendResponse(exchange, dataTypeHandler.createFunctionDefinitionFromPrototype(prototype, categoryPath));
        });
    }

    private void registerBulkEndpoints() {
        // Bulk rename functions
        server.createContext("/bulk_rename_functions", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            List<Map<String, String>> renames = parseJsonArray(body);
            HttpUtils.sendResponse(exchange, functionHandler.bulkRenameFunctions(renames));
        });

        // Bulk set function prototypes
        server.createContext("/bulk_set_function_prototypes", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            List<Map<String, String>> prototypes = parseJsonArray(body);
            HttpUtils.sendResponse(exchange, functionHandler.bulkSetFunctionPrototypes(prototypes));
        });

        // Bulk rename variables
        server.createContext("/bulk_rename_variables", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String renamesJson = params.get("renames");
            List<Map<String, String>> renames = parseJsonArray(renamesJson);
            HttpUtils.sendResponse(exchange, variableHandler.bulkRenameVariables(functionAddress, renames));
        });

        // Bulk set variable types
        server.createContext("/bulk_set_variable_types", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String typesJson = params.get("type_changes");
            List<Map<String, String>> typeChanges = parseJsonArray(typesJson);
            HttpUtils.sendResponse(exchange, variableHandler.bulkSetVariableTypes(functionAddress, typeChanges));
        });

        // Bulk rename structure fields
        server.createContext("/bulk_rename_structure_fields", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            String renamesJson = params.get("renames");
            List<Map<String, String>> renames = parseJsonArray(renamesJson);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkRenameStructureFields(structName, renames));
        });

        // Bulk retype structure fields
        server.createContext("/bulk_retype_structure_fields", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            String retypesJson = params.get("retypes");
            List<Map<String, String>> retypes = parseJsonArray(retypesJson);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkRetypeStructureFields(structName, retypes));
        });
    }

    /**
     * Simple JSON array parser for bulk operations.
     * Expects format: [{"key1":"val1","key2":"val2"},{"key1":"val3","key2":"val4"}]
     */
    private List<Map<String, String>> parseJsonArray(String json) {
        List<Map<String, String>> result = new ArrayList<>();
        if (json == null || json.isEmpty()) return result;

        // Remove whitespace and outer brackets
        json = json.trim();
        if (json.startsWith("[")) json = json.substring(1);
        if (json.endsWith("]")) json = json.substring(0, json.length() - 1);

        if (json.isEmpty()) return result;

        // Split by },{ to get individual objects
        int braceDepth = 0;
        int start = 0;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') braceDepth++;
            else if (c == '}') {
                braceDepth--;
                if (braceDepth == 0) {
                    String objStr = json.substring(start, i + 1).trim();
                    Map<String, String> obj = parseJsonObject(objStr);
                    if (!obj.isEmpty()) result.add(obj);
                    start = i + 1;
                    // Skip comma
                    while (start < json.length() && (json.charAt(start) == ',' || json.charAt(start) == ' ')) {
                        start++;
                    }
                }
            }
        }

        return result;
    }

    /**
     * Simple JSON object parser.
     * Expects format: {"key1":"val1","key2":"val2"}
     */
    private Map<String, String> parseJsonObject(String json) {
        Map<String, String> result = new HashMap<>();
        if (json == null || json.isEmpty()) return result;

        // Remove outer braces
        json = json.trim();
        if (json.startsWith("{")) json = json.substring(1);
        if (json.endsWith("}")) json = json.substring(0, json.length() - 1);

        // Parse key-value pairs
        boolean inQuotes = false;
        boolean inKey = true;
        StringBuilder key = new StringBuilder();
        StringBuilder value = new StringBuilder();

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            if (c == '"') {
                inQuotes = !inQuotes;
                continue;
            }

            if (!inQuotes) {
                if (c == ':') {
                    inKey = false;
                    continue;
                }
                if (c == ',') {
                    if (key.length() > 0) {
                        result.put(key.toString().trim(), value.toString().trim());
                    }
                    key = new StringBuilder();
                    value = new StringBuilder();
                    inKey = true;
                    continue;
                }
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
            }

            if (inKey) {
                key.append(c);
            } else {
                value.append(c);
            }
        }

        // Don't forget the last pair
        if (key.length() > 0) {
            result.put(key.toString().trim(), value.toString().trim());
        }

        return result;
    }

    /**
     * Simple JSON string array parser.
     * Expects format: ["val1","val2","val3"]
     */
    private List<String> parseJsonStringArray(String json) {
        List<String> result = new ArrayList<>();
        if (json == null || json.isEmpty()) return result;

        // Remove whitespace and outer brackets
        json = json.trim();
        if (json.startsWith("[")) json = json.substring(1);
        if (json.endsWith("]")) json = json.substring(0, json.length() - 1);

        if (json.isEmpty()) return result;

        // Parse string values
        boolean inQuotes = false;
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            if (c == '"') {
                inQuotes = !inQuotes;
                continue;
            }

            if (!inQuotes) {
                if (c == ',') {
                    String value = current.toString().trim();
                    if (!value.isEmpty()) {
                        result.add(value);
                    }
                    current = new StringBuilder();
                    continue;
                }
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
            }

            current.append(c);
        }

        // Don't forget the last value
        String value = current.toString().trim();
        if (!value.isEmpty()) {
            result.add(value);
        }

        return result;
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1);
            server = null;
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
