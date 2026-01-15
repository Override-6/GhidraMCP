package com.lauriewired.handlers;

import com.lauriewired.util.ThreadUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Handler for comment-related operations (decompiler and disassembly comments)
 */
public class CommentHandler {

    private final ProgramProvider programProvider;

    public CommentHandler(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    /**
     * Set a comment for a given address in the function pseudocode (PRE_COMMENT)
     */
    public boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly (EOL_COMMENT)
     */
    public boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            ThreadUtils.invokeAndWaitSafe(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set multiple comments in a single operation.
     *
     * @param comments List of {address, comment, type} entries.
     *                 type can be "decompiler" (PRE_COMMENT) or "disassembly" (EOL_COMMENT)
     * @return Result message with success/failure for each comment
     */
    public String bulkSetComments(List<Map<String, String>> comments) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (comments == null || comments.isEmpty()) return "Comments list is required";

        AtomicReference<String> result = new AtomicReference<>();
        StringBuilder sb = new StringBuilder();

        try {
            ThreadUtils.invokeAndWaitSafe(() -> {
                int tx = program.startTransaction("Bulk set comments");
                int successCount = 0;
                try {
                    for (Map<String, String> entry : comments) {
                        String addressStr = entry.get("address");
                        String comment = entry.get("comment");
                        String type = entry.getOrDefault("type", "decompiler");

                        if (addressStr == null || comment == null) {
                            sb.append("SKIP: Missing address or comment\n");
                            continue;
                        }

                        int commentType = "disassembly".equalsIgnoreCase(type)
                                ? CodeUnit.EOL_COMMENT
                                : CodeUnit.PRE_COMMENT;

                        try {
                            Address addr = program.getAddressFactory().getAddress(addressStr);
                            program.getListing().setComment(addr, commentType, comment);
                            sb.append("OK: ").append(addressStr).append(" [").append(type).append("]\n");
                            successCount++;
                        } catch (Exception e) {
                            sb.append("FAIL: ").append(addressStr).append(" - ").append(e.getMessage()).append("\n");
                        }
                    }

                    sb.insert(0, "Bulk set comments completed. Success: " + successCount + "/" + comments.size() + "\n");
                } finally {
                    program.endTransaction(tx, true);
                }
                result.set(sb.toString());
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to bulk set comments on Swing thread", e);
            return "Error: " + e.getMessage();
        }

        return result.get();
    }

}
