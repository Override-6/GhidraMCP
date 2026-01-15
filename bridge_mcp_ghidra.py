# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import json
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8081/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=30)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


# ============================================================================
# ANALYSIS INITIALIZATION - Call these at the start of analysis
# ============================================================================

@mcp.tool()
def search_functions_by_regex(pattern: str, offset: int = 0, limit: int = 100) -> list:
    """
    Use Cases:
    - Find functions with specific parameter types: ".*GameSession\\*.*"
    - Find functions in a namespace: "Player::.*" or "Village::.*"
    - Find functions returning specific types: "Player\\*.*Village::.*"
    - Check if a function name already exists before renaming

    Examples:
        search_functions_by_regex(".*Update.*Session.*")  # Find update session functions
        search_functions_by_regex(".*Player\\*.*")         # Functions with Player* parameter
        search_functions_by_regex("^get_.*")               # Functions starting with get_

    Returns: List of "full_name @ address | signature" for each match.
    """
    return safe_get("search_functions_by_regex", {"pattern": pattern, "offset": offset, "limit": limit})


@mcp.tool()
def search_strings_by_regex(pattern: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for defined strings using a regex pattern.

    Useful for finding error messages, debug strings, or string constants that
    give context to what functions do.

    Examples:
        search_strings_by_regex(".*error.*")      # Find error messages
        search_strings_by_regex(".*password.*")   # Find password-related strings
        search_strings_by_regex(".*config.*")     # Find configuration strings

    Returns: List of "label @ address: \"string_content\"" for each match.
    """
    return safe_get("search_strings_by_regex", {"pattern": pattern, "offset": offset, "limit": limit})


@mcp.tool()
def search_data_types_by_regex(pattern: str, offset: int = 0, limit: int = 100) -> list:
    """
    IMPORTANT: Call this before creating new data types to avoid duplicates.

    Search for existing data types (structures, enums, typedefs) by regex pattern.

    Use Cases:
    - Check if a structure already exists before creating one
    - Find related types by naming pattern
    - Discover existing game/application types

    Examples:
        search_data_types_by_regex(".*Player.*")   # Find Player-related types
        search_data_types_by_regex(".*Session.*")  # Find Session-related types
        search_data_types_by_regex(".*Config.*")   # Find configuration types

    Returns: List of "[TYPE_KIND] path/name (size: N bytes)" for each match.
    """
    return safe_get("search_data_types_by_regex", {"pattern": pattern, "offset": offset, "limit": limit})


# ============================================================================
# LISTING FUNCTIONS - Enumerate program elements
# ============================================================================

@mcp.tool()
def get_binary_info() -> str:
    """
    Get essential information about the loaded binary.

    IMPORTANT: Call this at the start of analysis to understand the binary's
    memory layout and architecture.

    Returns information including:
    - Image Base: The base address where the binary is loaded
    - Min/Max Address: The address range of the binary in memory
    - Program Name and Executable Path
    - Language/Architecture (e.g., x86:LE:64:default)
    - Compiler specification
    - Pointer Size: 4 bytes (32-bit) or 8 bytes (64-bit)
    - Total Memory Size
    - Function Count

    Example output:
        Image Base: 0x140000000
        Min Address: 0x140000000
        Max Address: 0x14fffffff
        Program Name: game.exe
        Language: x86:LE:64:default
        Pointer Size: 8 bytes (64-bit)
        Function Count: 12345

    Use the Image Base to calculate relative virtual addresses (RVA):
        RVA = absolute_address - image_base
    """
    return "\n".join(safe_get("get_binary_info"))


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the binary with pagination.

    Note: For large binaries, use search_functions_by_regex() instead
    to find specific functions efficiently.

    Returns: List of function names (without addresses).
    """
    return safe_get("methods", {"offset": offset, "limit": limit})


@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names found in the binary.

    Namespaces often represent C++ classes or logical groupings.
    Use this to understand the high-level structure of the codebase.

    Returns: List of namespace/class names.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments (sections) in the binary.

    Useful for understanding memory layout: .text (code), .data (initialized data),
    .bss (uninitialized data), .rodata (read-only data), etc.

    Returns: List of "segment_name: start_addr - end_addr".
    """
    return safe_get("segments", {"offset": offset, "limit": limit})


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols (external functions the binary uses).

    Imports reveal what libraries/APIs the binary uses, which helps
    understand its functionality (e.g., network, file I/O, crypto).

    Returns: List of "symbol_name -> address".
    """
    return safe_get("imports", {"offset": offset, "limit": limit})


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported symbols (functions/data exposed by the binary).

    For DLLs/shared libraries, these are the public API functions.
    For executables, typically includes the entry point.

    Returns: List of "symbol_name -> address".
    """
    return safe_get("exports", {"offset": offset, "limit": limit})


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program.

    Similar to list_classes but focuses on namespace hierarchy.

    Returns: List of namespace names.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values.

    Shows global variables, constants, and other defined data.

    Returns: List of "address: label = value".
    """
    return safe_get("data", {"offset": offset, "limit": limit})


@mcp.tool()
def list_functions() -> list:
    """
    List all functions with their addresses.

    Warning: For large binaries with thousands of functions, this may be slow.
    Consider using search_functions_by_regex() for targeted searches.

    Returns: List of "function_name at address".
    """
    return safe_get("list_functions")


@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the binary.

    Strings provide valuable context for understanding function behavior.
    Use the filter parameter for substring matching, or search_strings_by_regex()
    for pattern matching.

    Args:
        offset: Pagination offset
        limit: Max results (default 2000)
        filter: Optional substring filter (case-insensitive)

    Returns: List of "address: \"string_content\"".
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)


@mcp.tool()
def list_structures(offset: int = 0, limit: int = 100) -> list:
    """
    List all defined structures in the program.

    Use search_data_types_by_regex() to search for specific structures.

    Returns: List of "path/name (size: N, fields: M)".
    """
    return safe_get("list_structures", {"offset": offset, "limit": limit})


@mcp.tool()
def list_enums(offset: int = 0, limit: int = 100) -> list:
    """
    List all defined enums in the program.

    Returns: List of "path/name (values: N)".
    """
    return safe_get("list_enums", {"offset": offset, "limit": limit})


# ============================================================================
# FUNCTION ANALYSIS - Examine and understand functions
# ============================================================================

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a function by its exact name.

    Returns the decompiled C code with a header containing:
    - Function name
    - Entry point address
    - Full signature
    - Body address range

    Use decompile_function_by_address() if you have the address instead.

    Returns: Decompiled C code with metadata header.
    """
    return safe_post("decompile", name)


@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.

    The address can be the entry point or any address within the function body.
    Format: hex string like "0x1400010a0" or "1400010a0".

    Returns the decompiled C code with a header containing:
    - Function name
    - Entry point address
    - Full signature
    - Body address range

    Returns: Decompiled C code with metadata header.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))


@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get the assembly code for a function.

    Useful when decompilation doesn't capture low-level details,
    or for analyzing inline assembly, SIMD instructions, etc.

    Returns: List of "address: instruction ; comment".
    """
    return safe_get("disassemble_function", {"address": address})


@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get detailed information about a function at an address.

    Returns:
    - Function name
    - Entry point address
    - Signature
    - Body bounds (start - end address)
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))


# @mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions by substring match in their names.

    For more powerful pattern matching, use search_functions_by_regex().

    Returns: List of "name @ address" for matching functions.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})


@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected in the Ghidra GUI.

    Useful for working with the user's current focus point.
    """
    return "\n".join(safe_get("get_current_address"))


@mcp.tool()
def get_current_function() -> str:
    """
    Get information about the function at the current GUI cursor position.

    Returns the function name, address, and signature.
    """
    return "\n".join(safe_get("get_current_function"))


@mcp.tool()
def get_structure(name: str) -> str:
    """
    Get detailed information about a specific structure.

    Returns all fields with their offsets, types, and sizes.

    Example output:
        Structure: /MyTypes/GameSession
        Size: 64 bytes
        Alignment: 8
        Fields:
          +0x0: int session_id (size: 4)
          +0x8: Player* owner (size: 8)
          ...
    """
    return "\n".join(safe_get("get_structure", {"name": name}))


# ============================================================================
# CROSS-REFERENCES - Understand code relationships
# ============================================================================

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references TO a specific address (who calls/references this?).

    Essential for understanding how a function or data is used throughout
    the program. Shows the calling context for each reference.

    Args:
        address: Target address in hex (e.g., "0x1400010a0")
        offset: Pagination offset
        limit: Max results

    Returns: List of "From address in function_name [ref_type]".
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})


@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references FROM a specific address (what does this call/reference?).

    Shows what functions are called and what data is accessed from
    a specific location.

    Args:
        address: Source address in hex
        offset: Pagination offset
        limit: Max results

    Returns: List of "To address to function_name/data_label [ref_type]".
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})


@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to a function by its name.

    Equivalent to get_xrefs_to() but takes a function name instead of address.

    Returns: List of "From address in caller_function [ref_type]".
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})


# ============================================================================
# SINGLE RENAME/RETYPE OPERATIONS
# ============================================================================

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name.

    For bulk operations after analyzing a function, use bulk_rename_functions().

    Returns: Success/failure message.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})


@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.

    For bulk operations after analyzing a function, use bulk_rename_functions().

    Args:
        function_address: Function address in hex
        new_name: New name for the function

    Returns: Success/failure message.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})


@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.

    For bulk operations after analyzing a function, use bulk_rename_variables().

    Args:
        function_name: Name of the containing function
        old_name: Current variable name (e.g., "local_10", "param_1")
        new_name: New descriptive name

    Returns: Success/failure message.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })


@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at a specific address.

    Use for global variables, constants, and other data definitions.

    Returns: Success/failure message.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})


@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's full prototype (return type, name, parameters).

    For bulk operations, use bulk_set_function_prototypes().

    Args:
        function_address: Function address in hex
        prototype: Full C-style prototype, e.g., "int update_session(GameSession* session, int flags)"

    The prototype should include:
    - Return type
    - Function name
    - Parameters with types and names

    Example prototypes:
    - "void* malloc(size_t size)"
    - "int Player::update(float delta_time)"
    - "GameSession* create_session(int session_type, Player* owner)"

    Returns: Success/failure message with any warnings.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})


@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's data type.

    For bulk operations, use bulk_set_variable_types().

    Args:
        function_address: Function address in hex
        variable_name: Name of the variable to retype
        new_type: New type name (e.g., "int", "GameSession*", "Player")

    Supports:
    - Built-in types: int, uint, char, void, bool, etc.
    - Pointer types: Type* or PType (Windows-style)
    - Custom types: Any structure/typedef defined in the program

    Returns: Success/failure message.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})


# ============================================================================
# STRUCTURE FIELD OPERATIONS
# ============================================================================

@mcp.tool()
def rename_structure_field(structure_name: str, old_field_name: str, new_field_name: str) -> str:
    """
    Rename a field within a structure.

    For bulk operations, use bulk_rename_structure_fields().

    Args:
        structure_name: Name of the structure
        old_field_name: Current field name
        new_field_name: New descriptive name

    Returns: Success/failure message.
    """
    return safe_post("rename_structure_field", {
        "structure_name": structure_name,
        "old_field_name": old_field_name,
        "new_field_name": new_field_name
    })


@mcp.tool()
def retype_structure_field(structure_name: str, field_name: str, new_type: str) -> str:
    """
    Change the data type of a structure field.

    For bulk operations, use bulk_retype_structure_fields().

    Args:
        structure_name: Name of the structure
        field_name: Name of the field to retype
        new_type: New type for the field

    Returns: Success/failure message.
    """
    return safe_post("retype_structure_field", {
        "structure_name": structure_name,
        "field_name": field_name,
        "new_type": new_type
    })


@mcp.tool()
def add_structure_field(structure_name: str, field_name: str, field_type: str, offset: int = -1) -> str:
    """
    Add a new field to an existing structure.

    Args:
        structure_name: Name of the structure to modify
        field_name: Name for the new field
        field_type: Type of the new field
        offset: Byte offset for the field (-1 to append at end)

    Returns: Success/failure message.
    """
    return safe_post("add_structure_field", {
        "structure_name": structure_name,
        "field_name": field_name,
        "field_type": field_type,
        "offset": str(offset)
    })


@mcp.tool()
def bulk_add_structure_fields(structure_name: str, fields: list) -> str:
    """
    Add multiple fields to an existing structure in a single operation.

    Args:
        structure_name: Name of the structure to modify
        fields: List of field definitions, each with "name", "type", and optionally "offset"

    Example:
        bulk_add_structure_fields(
            structure_name="GameSession",
            fields=[
                {"name": "session_id", "type": "int", "offset": "0"},
                {"name": "player_count", "type": "int", "offset": "4"},
                {"name": "owner", "type": "Player*", "offset": "8"},
                {"name": "state", "type": "int", "offset": "16"},
                {"name": "flags", "type": "uint", "offset": "20"}
            ]
        )

    Example - Append fields (no offset specified):
        bulk_add_structure_fields(
            structure_name="Config",
            fields=[
                {"name": "setting1", "type": "int"},
                {"name": "setting2", "type": "float"},
                {"name": "name", "type": "char*"}
            ]
        )

    Returns: Summary with success/failure for each field and final structure size.
    """
    return safe_post("bulk_add_structure_fields", {
        "structure_name": structure_name,
        "fields": json.dumps(fields)
    })


# ============================================================================
# DATA TYPE CREATION
# ============================================================================

@mcp.tool()
def create_structure(name: str, category_path: str = "", size: int = 0, fields: list = None) -> str:
    """
    Create a new structure data type, optionally with fields.

    Args:
        name: Name for the new structure
        category_path: Optional category path (e.g., "/MyTypes", "/Game/Entities")
        size: Initial size in bytes (0 for auto-size based on fields)
        fields: Optional list of field definitions to add immediately.
                Each field is a dict with "name", "type", and optionally "offset".

    Example - Create empty structure:
        create_structure("Player", "/Game", 64)

    Example - Create structure with fields:
        create_structure(
            name="PlayerVTable",
            category_path="/VTables",
            size=0,
            fields=[
                {"name": "destructor", "type": "void*", "offset": "0"},
                {"name": "update", "type": "void*", "offset": "8"},
                {"name": "render", "type": "void*", "offset": "16"}
            ]
        )

    Returns: Success message with the full path and field results, or error if exists.
    """
    if fields:
        data = {
            "name": name,
            "category_path": category_path,
            "size": str(size),
            "fields": json.dumps(fields)
        }
        return safe_post("create_structure_with_fields", data)
    else:
        return safe_post("create_structure", {
            "name": name,
            "category_path": category_path,
            "size": str(size)
        })


@mcp.tool()
def create_enum(name: str, category_path: str = "", size: int = 4) -> str:
    """
    Create a new enum data type.

    Args:
        name: Name for the new enum
        category_path: Optional category path (e.g., "/MyTypes")
        size: Size in bytes (1, 2, 4, or 8)

    After creation, use add_enum_value() to add values.

    Returns: Success message with the full path, or error if exists.
    """
    return safe_post("create_enum", {
        "name": name,
        "category_path": category_path,
        "size": str(size)
    })


@mcp.tool()
def create_typedef(name: str, base_type: str, category_path: str = "") -> str:
    """
    Create a new typedef (type alias).

    Args:
        name: Name for the new typedef
        base_type: The type to alias (e.g., "int", "void*", "MyStruct*")
        category_path: Optional category path

    Example: create_typedef("HANDLE", "void*") creates "typedef void* HANDLE;"

    Returns: Success message with the full path, or error if exists.
    """
    return safe_post("create_typedef", {
        "name": name,
        "base_type": base_type,
        "category_path": category_path
    })


@mcp.tool()
def add_enum_value(enum_name: str, value_name: str, value: int) -> str:
    """
    Add a value to an existing enum.

    Args:
        enum_name: Name of the enum to modify
        value_name: Name for the new enum value
        value: Numeric value

    Returns: Success/failure message.
    """
    return safe_post("add_enum_value", {
        "enum_name": enum_name,
        "value_name": value_name,
        "value": str(value)
    })


@mcp.tool()
def resize_structure(structure_name: str, new_size: int) -> str:
    """
    Resize a structure to a specific size.

    Use this when you need to grow or shrink a structure to accommodate
    more fields or to match an expected size.

    Args:
        structure_name: Name of the structure to resize
        new_size: New size in bytes

    Notes:
    - Growing the structure adds undefined bytes at the end
    - Shrinking the structure removes fields that extend beyond the new size
    - Size must be positive

    Returns: Success message with old and new sizes, or error message.
    """
    return safe_post("resize_structure", {
        "structure_name": structure_name,
        "new_size": str(new_size)
    })


@mcp.tool()
def create_function_definition(
    name: str,
    return_type: str,
    parameter_types: list = None,
    parameter_names: list = None,
    category_path: str = ""
) -> str:
    """
    Create a new function definition (function type) for use in structures.

    Function definitions are essential for properly typing vtable entries and
    function pointers in structures. They define the signature of a function
    without providing an implementation.

    Args:
        name: Name for the function type (e.g., "UpdateFunc", "VTable_Draw")
        return_type: Return type (e.g., "void", "int", "Player*")
        parameter_types: List of parameter types (e.g., ["void*", "int", "float"])
        parameter_names: List of parameter names (e.g., ["this", "param1", "delta"])
        category_path: Optional category path (e.g., "/VTables", "/FunctionTypes")

    Example - Creating a vtable method type:
        create_function_definition(
            name="VTable_Update",
            return_type="void",
            parameter_types=["Player*", "float"],
            parameter_names=["this", "deltaTime"],
            category_path="/VTables"
        )

    After creation, use this type in a structure field:
        add_structure_field("PlayerVTable", "update", "VTable_Update*")

    Returns: Success message with signature, or error if exists.
    """
    data = {
        "name": name,
        "return_type": return_type,
        "category_path": category_path
    }
    if parameter_types:
        data["parameter_types"] = json.dumps(parameter_types)
    if parameter_names:
        data["parameter_names"] = json.dumps(parameter_names)
    return safe_post("create_function_definition", data)


@mcp.tool()
def create_function_definition_from_prototype(prototype: str, category_path: str = "") -> str:
    """
    Create a function definition from a C-style prototype string.

    This is a convenient way to create function types using familiar C syntax.
    Useful for quickly defining vtable methods or function pointer types.

    Args:
        prototype: C-style function prototype string
        category_path: Optional category path (e.g., "/VTables")

    Example prototypes:
    - "void UpdatePlayer(Player* this, float deltaTime)"
    - "int GetHealth(Entity* this)"
    - "void* CreateInstance(int type, size_t size)"
    - "bool ValidateInput(const char* input, int length)"

    For function pointers (the name becomes the type name):
    - "void (*DrawFunc)(Canvas* canvas, int x, int y)"

    Returns: Success message with parsed signature, or error message.
    """
    return safe_post("create_function_definition_from_prototype", {
        "prototype": prototype,
        "category_path": category_path
    })


# ============================================================================
# BULK OPERATIONS - Use after analyzing a function
# ============================================================================

@mcp.tool()
def bulk_rename_functions(renames: list) -> str:
    """
    Rename multiple functions in a single operation.

    RECOMMENDED: Use this after analyzing a function to apply all your
    renaming decisions at once, rather than making individual calls.

    Args:
        renames: List of dicts with "address" and "new_name" keys
                 Example: [{"address": "0x1400010a0", "new_name": "init_player"},
                          {"address": "0x140001200", "new_name": "update_player"}]

    Returns: Summary with success/failure for each rename.
    """
    return safe_post("bulk_rename_functions", json.dumps(renames))


@mcp.tool()
def bulk_set_function_prototypes(prototypes: list) -> str:
    """
    Set prototypes for multiple functions in a single operation.

    RECOMMENDED: Use this after analyzing a function to apply all your
    prototype changes at once.

    Args:
        prototypes: List of dicts with "address" and "prototype" keys
                    Example: [{"address": "0x1400010a0", "prototype": "void init_player(Player* p)"},
                             {"address": "0x140001200", "prototype": "int update_player(Player* p, float dt)"}]

    Returns: Summary with success/failure for each operation.
    """
    return safe_post("bulk_set_function_prototypes", json.dumps(prototypes))


@mcp.tool()
def bulk_rename_variables(function_address: str, renames: list) -> str:
    """
    Rename multiple variables within a single function.

    RECOMMENDED: Use this after analyzing a function to apply all your
    variable naming decisions at once.

    Args:
        function_address: Address of the function containing the variables
        renames: List of dicts with "old_name" and "new_name" keys
                 Example: [{"old_name": "local_10", "new_name": "player_ptr"},
                          {"old_name": "local_18", "new_name": "session_id"}]

    Returns: Summary with success/failure for each rename.
    """
    return safe_post("bulk_rename_variables", {
        "function_address": function_address,
        "renames": json.dumps(renames)
    })


@mcp.tool()
def bulk_set_variable_types(function_address: str, type_changes: list) -> str:
    """
    Set types for multiple variables within a single function.

    RECOMMENDED: Use this after analyzing a function to apply all your
    type changes at once.

    Args:
        function_address: Address of the function containing the variables
        type_changes: List of dicts with "variable_name" and "new_type" keys
                      Example: [{"variable_name": "player_ptr", "new_type": "Player*"},
                               {"variable_name": "session_id", "new_type": "int"}]

    Returns: Summary with success/failure for each type change.
    """
    return safe_post("bulk_set_variable_types", {
        "function_address": function_address,
        "type_changes": json.dumps(type_changes)
    })


@mcp.tool()
def bulk_rename_structure_fields(structure_name: str, renames: list) -> str:
    """
    Rename multiple fields within a structure.

    Args:
        structure_name: Name of the structure
        renames: List of dicts with "old_name" and "new_name" keys
                 Example: [{"old_name": "field_0x10", "new_name": "player_id"},
                          {"old_name": "field_0x18", "new_name": "session_ptr"}]

    Returns: Summary with success/failure for each rename.
    """
    return safe_post("bulk_rename_structure_fields", {
        "structure_name": structure_name,
        "renames": json.dumps(renames)
    })


@mcp.tool()
def bulk_retype_structure_fields(structure_name: str, retypes: list) -> str:
    """
    Change types for multiple fields within a structure.

    Args:
        structure_name: Name of the structure
        retypes: List of dicts with "field_name" and "new_type" keys
                 Example: [{"field_name": "player_id", "new_type": "int"},
                          {"field_name": "session_ptr", "new_type": "GameSession*"}]

    Returns: Summary with success/failure for each retype.
    """
    return safe_post("bulk_retype_structure_fields", {
        "structure_name": structure_name,
        "retypes": json.dumps(retypes)
    })


# ============================================================================
# COMMENTS - Annotate the binary
# ============================================================================

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Add a comment that appears in the decompiled pseudocode.

    Use for explaining complex logic, noting assumptions, or
    documenting your analysis findings.

    Args:
        address: Address for the comment (appears before the statement)
        comment: Comment text

    Returns: Success/failure message.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})


@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Add a comment that appears in the disassembly listing.

    Use for assembly-level notes, register usage, or instruction details.

    Args:
        address: Address for the comment (appears at end of line)
        comment: Comment text

    Returns: Success/failure message.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()

    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()

if __name__ == "__main__":
    main()
