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
    private static final int DEFAULT_PORT = 8080;

    // Handlers
    private ListingHandler listingHandler;
    private FunctionHandler functionHandler;
    private VariableHandler variableHandler;
    private ReferenceHandler referenceHandler;
    private CommentHandler commentHandler;

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
