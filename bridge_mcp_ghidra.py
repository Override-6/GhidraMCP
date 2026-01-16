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


def safe_post_json(endpoint: str, data: dict) -> str:
    """
    Perform a POST request with JSON body.
    """
    try:
        url = urljoin(ghidra_server_url, endpoint)
        response = requests.post(url, json=data, timeout=60)
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

    IMPORTANT: PREFER bulk_decompile_function_diff() IF YOU HAVE THE ADDRESS TO SAVE TOKENS!

    Returns: Decompiled C code with metadata header.
    """
    return safe_post("decompile", name)


@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.

    The address can be the entry point or any address within the function body.
    Format: hex string like "0x1400010a0" or "1400010a0".

    IMPORTANT: PREFER bulk_decompile_function_diff() IF YOU HAVE THE ADDRESS TO SAVE TOKENS!

    Returns the decompiled C code with a header containing:
    - Function name
    - Entry point address
    - Full signature
    - Body address range

    Returns: Decompiled C code with metadata header.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))


@mcp.tool()
def decompile_function_with_context(address: str) -> str:
    """
    Decompile a function and return comprehensive context for analysis.

    This is the RECOMMENDED way to decompile functions as it provides all the
    context needed to understand and modify the function in one call.

    Returns:
    - Decompiled C code with function metadata (name, address, signature)
    - All type definitions used in the function (structures, enums, function types)
    - All called function prototypes with their addresses

    Args:
        address: Function address in hex (e.g., "0x1400010a0")

    Use this before calling commit_function_analysis() to understand:
    - What types need to be created or modified
    - What called functions might need renaming
    - Variable types and names that can be improved

    Returns: Comprehensive decompilation with full context.
    """
    return "\n".join(safe_get("decompile_function_with_context", {"address": address}))

@mcp.tool()
def bulk_decompile_function_diff(addresses: list, context_lines: int = 0) -> list:
    """
    Decompiles the given functions and returns the difference between their current C representation with their previous ones.
    This allows you to consume less tokens when you want to verify the results of the actions you performed on functions after their last decompilation.
    Should be preferred from decompile_function and decompile_function_by_address.

    The goal of this function is to save tokens by avoiding you to have to process the whole function code.
    However, it is possible that this function still returns the full code for some functions if they had so much diff since last decompile that the diff is actually longer / harder to process than just returning the whole code.
    This function should always be preferred for verification.

    Args:
        addresses: Functions addresses in hex string (e.g., ["0x1400010a0", ...])
        context_lines: (default 0) lines to show before and after each diff for more context.

    Returns: Comprehensive difference between last decompilation and current C code representation.

    """
    return safe_post_json("bulk_function_diff", {"addresses": addresses, "context_lines": str(context_lines)})

@mcp.tool()
def bulk_get_functions_signatures_by_address(addresses: list) -> str:
    """
    Returns ONLY the function signatures of given function addresses without decompilation.
    Use case: Quick verification after changes without full decompile cost.

    Args:
        addresses: Functions addresses in hex string (e.g., ["0x1400010a0", ...])

    Returns: string containing all functions signatures associated with their addresses

    """
    return safe_post("bulk_get_signatures", json.dumps(addresses))

@mcp.tool()
def get_function_signature_only(address: str) -> str:
    """
    Returns ONLY the function signature without decompilation.

    Returns: "void game_state_update(GameStateManager *mgr, float delta_time)"

    Use case: Quick verification after changes without full decompile cost.
    Cost: ~50-100 tokens vs 2000+ for full decompile
    """
    return bulk_get_functions_signatures_by_address([address])


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
# DATA OPERATIONS - Rename data labels
# ============================================================================

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at a specific address.

    Use for global variables, constants, and other data definitions.

    Returns: Success/failure message.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})


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
def create_enum(name: str, category_path: str = "", size: int = 4, values: list = None) -> str:
    """
    Create a new enum data type, optionally with values.

    Args:
        name: Name for the new enum
        category_path: Optional category path (e.g., "/MyTypes")
        size: Size in bytes (1, 2, 4, or 8)
        values: Optional list of value definitions to add immediately.
                Each value is a dict with "name" and "value" keys.

    Example - Create enum with values:
        create_enum(
            name="GameState",
            category_path="/Game",
            size=4,
            values=[
                {"name": "STATE_INIT", "value": 0},
                {"name": "STATE_RUNNING", "value": 1},
                {"name": "STATE_PAUSED", "value": 2}
            ]
        )

    Returns: Success message with the full path, or error if exists.
    """
    if values:
        return safe_post("create_enum_with_values", {
            "name": name,
            "category_path": category_path,
            "size": str(size),
            "values": json.dumps(values)
        })
    else:
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
# BULK OPERATIONS - Efficient batch modifications
# ============================================================================

@mcp.tool()
def bulk_rename_functions(renames: list) -> str:
    """
    Rename multiple functions in a single operation.

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
    If you want to change parameter types, please do it by changing the function's prototype.

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


@mcp.tool()
def bulk_update_structure_fields(structure_name: str, fields: list) -> str:
    """
    Update multiple fields in an existing structure (add or replace at offset).

    Args:
        structure_name: Name of the structure to modify
        fields: List of field definitions, each with "name", "type", and optionally "offset"

    Example:
        bulk_update_structure_fields(
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
        bulk_update_structure_fields(
            structure_name="Config",
            fields=[
                {"name": "setting1", "type": "int"},
                {"name": "setting2", "type": "float"},
                {"name": "name", "type": "char*"}
            ]
        )

    Returns: Summary with success/failure for each field and final structure size.
    """
    return safe_post("bulk_update_structure_fields", {
        "structure_name": structure_name,
        "fields": json.dumps(fields)
    })


@mcp.tool()
def bulk_get_xrefs(addresses: list, limit: int = 100) -> str:
    """
    Get cross-references for multiple addresses in a single operation.

    Args:
        addresses: List of dicts with "address" and optionally "direction" (to/from/both)
                   Example: [{"address": "0x1400010a0", "direction": "both"},
                            {"address": "0x140001200", "direction": "to"}]
        limit: Max refs per address (default 100)

    Returns: Combined xref results for all addresses.
    """
    return safe_post_json("bulk_get_xrefs", {"addresses": addresses, "limit": limit})


@mcp.tool()
def bulk_rename_data(renames: list) -> str:
    """
    Rename multiple data labels at different addresses in a single operation.

    Args:
        renames: List of dicts with "address" and "new_name" keys
                 Example: [{"address": "0x1400010a0", "new_name": "g_player_count"},
                          {"address": "0x140001200", "new_name": "g_session_ptr"}]

    Returns: Summary with success/failure for each rename.
    """
    return safe_post("bulk_rename_data", json.dumps(renames))


@mcp.tool()
def bulk_resize_structures(resizes: list) -> str:
    """
    Resize multiple structures in a single operation.

    Args:
        resizes: List of dicts with "structure_name" and "new_size" keys
                 Example: [{"structure_name": "Player", "new_size": "128"},
                          {"structure_name": "Session", "new_size": "256"}]

    Returns: Summary with success/failure for each resize.
    """
    return safe_post("bulk_resize_structures", json.dumps(resizes))


@mcp.tool()
def bulk_get_structures(names: list) -> str:
    """
    Get details for multiple structures in a single operation.

    Args:
        names: List of structure names to retrieve
               Example: ["Player", "Session", "GameState"]

    Returns: Combined structure details for all requested structures.
    """
    return safe_post("bulk_get_structures", json.dumps(names))


@mcp.tool()
def bulk_add_enum_values(values: list) -> str:
    """
    Add multiple values to existing enums in a single operation.

    Args:
        values: List of dicts with "enum_name", "value_name", and "value" keys
                Example: [{"enum_name": "GameState", "value_name": "STATE_LOADING", "value": "3"},
                         {"enum_name": "GameState", "value_name": "STATE_ERROR", "value": "4"}]

    Returns: Summary with success/failure for each addition.
    """
    return safe_post("bulk_add_enum_values", json.dumps(values))


@mcp.tool()
def bulk_create_typedefs(typedefs: list) -> str:
    """
    Create multiple typedefs in a single operation.

    Args:
        typedefs: List of dicts with "name", "base_type", and optionally "category_path"
                  Example: [{"name": "HANDLE", "base_type": "void*"},
                           {"name": "PlayerPtr", "base_type": "Player*", "category_path": "/Game"}]

    Returns: Summary with success/failure for each typedef.
    """
    return safe_post("bulk_create_typedefs", json.dumps(typedefs))


@mcp.tool()
def bulk_set_comments(comments: list) -> str:
    """
    Set multiple comments in a single operation.

    Args:
        comments: List of dicts with "address", "comment", and optionally "type"
                  type can be "decompiler" (default) or "disassembly"
                  Example: [{"address": "0x1400010a0", "comment": "Initialize player", "type": "decompiler"},
                           {"address": "0x140001200", "comment": "Check bounds", "type": "disassembly"}]

    Returns: Summary with success/failure for each comment.
    """
    return safe_post("bulk_set_comments", json.dumps(comments))


# ============================================================================
# UNDO/REDO - Cancel or restore actions
# ============================================================================

@mcp.tool()
def undo() -> str:
    """
    Undo the last action/transaction.

    This cancels the most recent change made to the program database.
    Use this to revert mistakes or unwanted changes.

    Returns: Success/failure message.
    """
    return "\n".join(safe_get("undo"))


@mcp.tool()
def redo() -> str:
    """
    Redo the last undone action.

    This restores a change that was previously undone.

    Returns: Success/failure message.
    """
    return "\n".join(safe_get("redo"))


# ============================================================================
# COMMIT FUNCTION ANALYSIS - Apply all changes in one operation
# ============================================================================

@mcp.tool()
def commit_function_analysis(
    function_address: str,
    types: list = None,
    structures: list = None,
    new_signature: str = None,
    variable_changes: list = None,
    called_functions: list = None
) -> str:
    """
    Apply all analysis changes for a function in a single atomic operation.

    This is the RECOMMENDED way to commit changes after analyzing a function.
    It ensures all related changes are applied together in a single transaction.

    Args:
        function_address: Address of the function being analyzed (REQUIRED)

        types: List of enums or function types to create (optional)
            Each entry has: "kind" ("enum" or "function"), plus type-specific fields
            Example: [
                {
                    "kind": "enum",
                    "name": "RequestType",
                    "values": [{"name": "REQ_GET", "value": 0}, {"name": "REQ_POST", "value": 1}]
                },
                {
                    "kind": "function",
                    "prototype": "void (*Callback)(Session* s, int result)"
                }
            ]

       structures: List of structures to create or modify (optional)
            Each entry has: "name", "category_path" (optional), "size" (optional), "fields"
            Those defined structures can directly reuse types defined in the 'types' parameter
            Example: [
                {
                    "name": "Session",
                    "category_path": "/Game",
                    "fields": [
                        {"name": "id", "type": "int", "offset": "0"},
                        {"name": "player", "type": "Player*", "offset": "8"}
                    ]
                }
            ]

        new_signature: New function prototype (optional)
            Example: "int process_request(Session* session, Request* req)"

        variable_changes: List of variable modifications (optional)
            Each entry can have: "old_name", "new_name", "new_type"
            To change parameter variables, please just insert it in the new_signature argument !
            Defined variable types can directly reuse structures defined by the 'structures' and 'types' parameters
            Example: [
                {"old_name": "local_10", "new_name": "session", "new_type": "Session*"},
                {"old_name": "local_20", "new_type": "int"}
            ]


        called_functions: List of called function prototypes to update (optional)
            Each entry has: "address" and "prototype"
            Example: [
                {"address": "0x140001200", "prototype": "void send_response(Session* s, int code)"}
            ]

    Returns: Summary of all applied changes with success/failure status for each.

    Example usage:
        commit_function_analysis(
            function_address="0x1400010a0",
            structures=[
                {
                    "name": "Request",
                    "fields": [
                        {"name": "type", "type": "int", "offset": "0"},
                        {"name": "data", "type": "void*", "offset": "8"}
                    ]
                }
            ],
            new_signature="int handle_request(Session* session, Request* req)",
            variable_changes=[
                {"old_name": "local_10", "new_name": "session", "new_type": "Session*"},
                {"old_name": "local_18", "new_name": "request", "new_type": "Request*"}
            ],
            called_functions=[
                {"address": "0x140001500", "prototype": "void log_request(Request* req)"}
            ]
        )
    """
    payload = {
        "function_address": function_address
    }

    if new_signature:
        payload["new_signature"] = new_signature

    if variable_changes:
        payload["variable_changes"] = variable_changes

    if structures:
        payload["structures"] = structures

    if types:
        payload["types"] = types

    if called_functions:
        payload["called_functions"] = called_functions

    return safe_post_json("commit_function_analysis", payload)


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
