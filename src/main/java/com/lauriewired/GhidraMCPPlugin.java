package com.lauriewired;

import com.lauriewired.util.StringUtils;
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
import com.lauriewired.util.HttpUtils;
import com.lauriewired.util.JsonUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
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
        ProgramProvider programProvider = new ProgramProvider() {

            @Override
            public Program getCurrentProgram() {
                return GhidraMCPPlugin.this.getCurrentProgram();
            }

            @Override
            public PluginTool getTool() {
                return tool;
            }
        };

        listingHandler = new ListingHandler(programProvider);
        functionHandler = new FunctionHandler(programProvider);
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
        registerUndoEndpoints();

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
        // Decompile by name
        server.createContext("/decompile", exchange -> {
            String name = HttpUtils.readRequestBody(exchange);
            HttpUtils.sendResponse(exchange, functionHandler.decompileFunctionByName(name));
        });

        // Get function by address
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionHandler.getFunctionByAddress(address));
        });

        // Get current address in GUI
        server.createContext("/get_current_address", exchange -> {
            HttpUtils.sendResponse(exchange, functionHandler.getCurrentAddress());
        });

        // Get current function in GUI
        server.createContext("/get_current_function", exchange -> {
            HttpUtils.sendResponse(exchange, functionHandler.getCurrentFunction());
        });

        // Decompile by address
        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionHandler.decompileFunctionByAddress(address));
        });

        // Decompile with full context (types, called functions)
        server.createContext("/decompile_function_with_context", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionHandler.decompileFunctionWithContext(address));
        });

        // Disassemble function
        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionHandler.disassembleFunction(address));
        });

        // Commit function analysis (unified endpoint)
        server.createContext("/commit_function_analysis", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            Map<String, Object> payload = JsonUtils.parseJsonObjectDeep(body);
            HttpUtils.sendResponse(exchange, functionHandler.commitFunctionAnalysis(payload, dataTypeHandler, variableHandler));
        });
    }

    private void registerVariableEndpoints() {
        // Rename data at address
        server.createContext("/renameData", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            variableHandler.renameDataAtAddress(params.get("address"), params.get("newName"));
            HttpUtils.sendResponse(exchange, "Rename data attempted");
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
        // Search functions by regex pattern
        server.createContext("/search_functions_by_regex", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, searchHandler.searchFunctionsByRegex(pattern, offset, limit));
        });

        // Search strings by regex pattern
        server.createContext("/search_strings_by_regex", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, searchHandler.searchStringsByRegex(pattern, offset, limit));
        });

        // Search data types by regex pattern
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
            List<Map<String, String>> fields = JsonUtils.parseJsonArray(fieldsJson);
            HttpUtils.sendResponse(exchange, dataTypeHandler.createStructureWithFields(name, categoryPath, size, fields));
        });

        // Create new enum
        server.createContext("/create_enum", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String name = params.get("name");
            String categoryPath = params.get("category_path");
            int size = HttpUtils.parseIntOrDefault(params.get("size"), 4);
            HttpUtils.sendResponse(exchange, dataTypeHandler.createEnum(name, categoryPath, size));
        });

        // Create new enum with values
        server.createContext("/create_enum_with_values", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String name = params.get("name");
            String categoryPath = params.get("category_path");
            int size = HttpUtils.parseIntOrDefault(params.get("size"), 4);
            String valuesJson = params.get("values");
            List<Map<String, String>> values = JsonUtils.parseJsonArray(valuesJson);
            HttpUtils.sendResponse(exchange, dataTypeHandler.createEnumWithValues(name, categoryPath, size, values));
        });

        // Create new typedef
        server.createContext("/create_typedef", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String name = params.get("name");
            String baseType = params.get("base_type");
            String categoryPath = params.get("category_path");
            HttpUtils.sendResponse(exchange, dataTypeHandler.createTypedef(name, baseType, categoryPath));
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

            List<String> paramTypes = JsonUtils.parseJsonStringArray(paramTypesJson);
            List<String> paramNames = JsonUtils.parseJsonStringArray(paramNamesJson);

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
            String body = HttpUtils.readRequestBody(exchange);
            List<Map<String, String>> renames = JsonUtils.parseJsonArray(body);
            HttpUtils.sendResponse(exchange, functionHandler.bulkRenameFunctions(renames));
        });

        // Bulk set function prototypes
        server.createContext("/bulk_set_function_prototypes", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            List<Map<String, String>> prototypes = JsonUtils.parseJsonArray(body);
            HttpUtils.sendResponse(exchange, functionHandler.bulkSetFunctionPrototypes(prototypes));
        });

        // Bulk rename variables
        server.createContext("/bulk_rename_variables", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String renamesJson = params.get("renames");
            List<Map<String, String>> renames = JsonUtils.parseJsonArray(renamesJson);
            HttpUtils.sendResponse(exchange, variableHandler.bulkRenameVariables(functionAddress, renames));
        });

        // Bulk set variable types
        server.createContext("/bulk_set_variable_types", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String typesJson = params.get("type_changes");
            List<Map<String, String>> typeChanges = JsonUtils.parseJsonArray(typesJson);
            HttpUtils.sendResponse(exchange, variableHandler.bulkSetVariableTypes(functionAddress, typeChanges));
        });

        // Bulk rename structure fields
        server.createContext("/bulk_rename_structure_fields", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            String renamesJson = params.get("renames");
            List<Map<String, String>> renames = JsonUtils.parseJsonArray(renamesJson);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkRenameStructureFields(structName, renames));
        });

        // Bulk retype structure fields
        server.createContext("/bulk_retype_structure_fields", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            String retypesJson = params.get("retypes");
            List<Map<String, String>> retypes = JsonUtils.parseJsonArray(retypesJson);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkRetypeStructureFields(structName, retypes));
        });

        // Bulk update structure fields (replaces bulk_add_structure_fields)
        server.createContext("/bulk_update_structure_fields", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String structName = params.get("structure_name");
            String fieldsJson = params.get("fields");
            List<Map<String, String>> fields = JsonUtils.parseJsonArray(fieldsJson);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkUpdateStructureFields(structName, fields));
        });

        // Bulk get xrefs
        server.createContext("/bulk_get_xrefs", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            Map<String, Object> payload = JsonUtils.parseJsonObjectDeep(body);
            @SuppressWarnings("unchecked")
            List<Map<String, String>> addresses = (List<Map<String, String>>) (List<?>) payload.get("addresses");
            int limit = payload.containsKey("limit") ? ((Number) payload.get("limit")).intValue() : 100;
            HttpUtils.sendResponse(exchange, referenceHandler.bulkGetXrefs(addresses, limit));
        });

        // Bulk rename data
        server.createContext("/bulk_rename_data", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            List<Map<String, String>> renames = JsonUtils.parseJsonArray(body);
            HttpUtils.sendResponse(exchange, variableHandler.bulkRenameData(renames));
        });

        // Bulk resize structures
        server.createContext("/bulk_resize_structures", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            List<Map<String, String>> resizes = JsonUtils.parseJsonArray(body);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkResizeStructures(resizes));
        });

        // Bulk get structures
        server.createContext("/bulk_get_structures", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            List<String> names = JsonUtils.parseJsonStringArray(body);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkGetStructures(names));
        });

        // Bulk add enum values
        server.createContext("/bulk_add_enum_values", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            List<Map<String, String>> values = JsonUtils.parseJsonArray(body);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkAddEnumValues(values));
        });

        // Bulk create typedefs
        server.createContext("/bulk_create_typedefs", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            List<Map<String, String>> typedefs = JsonUtils.parseJsonArray(body);
            HttpUtils.sendResponse(exchange, dataTypeHandler.bulkCreateTypedefs(typedefs));
        });

        // Bulk set comments
        server.createContext("/bulk_set_comments", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            List<Map<String, String>> comments = JsonUtils.parseJsonArray(body);
            HttpUtils.sendResponse(exchange, commentHandler.bulkSetComments(comments));
        });

        server.createContext("/bulk_function_diff", exchange -> {
            try {
                String body = HttpUtils.readRequestBody(exchange);
                Map<String, Object> payload = JsonUtils.parseJsonObjectDeep(body);
                List<String> addresses = (List<String>) payload.get("addresses");
                int context_lines = StringUtils.parseInt((String) payload.getOrDefault("context_lines", "0"));
                HttpUtils.sendResponse(exchange, functionHandler.bulkGetDecompilationDiff(addresses, context_lines));
            } catch (Throwable e) {
                Msg.error(this, "error", e);
            };
        });

        server.createContext("/bulk_get_signatures", exchange -> {
            String body = HttpUtils.readRequestBody(exchange);
            List<String> addresses = JsonUtils.parseJsonStringArray(body);
            HttpUtils.sendResponse(exchange, functionHandler.bulkGetSignatures(addresses));
        });
    }

    private void registerUndoEndpoints() {
        // Undo last action
        server.createContext("/undo", exchange -> {
            Program program = getCurrentProgram();
            if (program == null) {
                HttpUtils.sendResponse(exchange, "No program loaded");
                return;
            }

            try {
                javax.swing.SwingUtilities.invokeAndWait(() -> {
                    try {
                        program.undo();
                    } catch (Exception e) {
                        Msg.error(this, "Undo failed", e);
                    }
                });
                HttpUtils.sendResponse(exchange, "Undo successful");
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, "Undo failed: " + e.getMessage());
            }
        });

        // Redo last undone action
        server.createContext("/redo", exchange -> {
            Program program = getCurrentProgram();
            if (program == null) {
                HttpUtils.sendResponse(exchange, "No program loaded");
                return;
            }

            try {
                javax.swing.SwingUtilities.invokeAndWait(() -> {
                    try {
                        program.redo();
                    } catch (Exception e) {
                        Msg.error(this, "Redo failed", e);
                    }
                });
                HttpUtils.sendResponse(exchange, "Redo successful");
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, "Redo failed: " + e.getMessage());
            }
        });
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
