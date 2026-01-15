package com.lauriewired.handlers;

import com.lauriewired.util.HttpUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Handler for cross-reference (xref) operations
 */
public class ReferenceHandler {

    private final ProgramProvider programProvider;

    public ReferenceHandler(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    /**
     * Get all references to a specific address (xref to)
     */
    public String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            return HttpUtils.paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    public String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();

            Reference[] references = refManager.getReferencesFrom(addr);

            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }

                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }

            return HttpUtils.paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    public String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);

                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();

                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }

            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }

            return HttpUtils.paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

    /**
     * Get cross-references for multiple addresses in a single operation.
     *
     * @param addresses List of maps with "address" and optionally "direction" (to/from/both)
     * @param limit Max refs per address
     * @return Combined results for all addresses
     */
    public String bulkGetXrefs(List<Map<String, String>> addresses, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addresses == null || addresses.isEmpty()) return "Address list is required";

        StringBuilder result = new StringBuilder();
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();

        for (Map<String, String> entry : addresses) {
            String addressStr = entry.get("address");
            String direction = entry.getOrDefault("direction", "to");

            if (addressStr == null || addressStr.isEmpty()) {
                result.append("SKIP: Missing address\n");
                continue;
            }

            try {
                Address addr = program.getAddressFactory().getAddress(addressStr);
                result.append("=== ").append(addressStr).append(" ===\n");

                // Get xrefs TO this address
                if ("to".equalsIgnoreCase(direction) || "both".equalsIgnoreCase(direction)) {
                    result.append("[XREFS TO]\n");
                    ReferenceIterator refIter = refManager.getReferencesTo(addr);
                    int count = 0;
                    while (refIter.hasNext() && count < limit) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        result.append("  From ").append(fromAddr).append(funcInfo)
                              .append(" [").append(refType.getName()).append("]\n");
                        count++;
                    }
                    if (count == 0) result.append("  (none)\n");
                }

                // Get xrefs FROM this address
                if ("from".equalsIgnoreCase(direction) || "both".equalsIgnoreCase(direction)) {
                    result.append("[XREFS FROM]\n");
                    Reference[] references = refManager.getReferencesFrom(addr);
                    int count = 0;
                    for (Reference ref : references) {
                        if (count >= limit) break;
                        Address toAddr = ref.getToAddress();
                        RefType refType = ref.getReferenceType();
                        String targetInfo = "";
                        Function toFunc = funcManager.getFunctionAt(toAddr);
                        if (toFunc != null) {
                            targetInfo = " to " + toFunc.getName();
                        }
                        result.append("  To ").append(toAddr).append(targetInfo)
                              .append(" [").append(refType.getName()).append("]\n");
                        count++;
                    }
                    if (count == 0) result.append("  (none)\n");
                }

            } catch (Exception e) {
                result.append("ERROR: ").append(e.getMessage()).append("\n");
            }
        }

        return result.toString();
    }

}
