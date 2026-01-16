package com.lauriewired.util;

import com.github.difflib.DiffUtils;
import com.github.difflib.UnifiedDiffUtils;
import com.github.difflib.patch.Patch;

import java.util.Arrays;
import java.util.List;

/**
 * Utility class for string manipulation operations
 */
public class StringUtils {

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    public static String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Escape special characters in a string for display
     */
    public static String escapeString(String input) {
        if (input == null) return "";

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int) c & 0xFF));
            }
        }
        return sb.toString();
    }

    public static int parseInt(String input) {
        if (input == null) return 0;
        if (input.startsWith("0x")) {
            return Integer.parseInt(input.substring(2), 16);
        }
        return Integer.parseInt(input);
    }


    /**
     * Generates a token-efficient diff specifically for LLM consumption.
     * * @param fileName The name of the file (helps LLM context)
     *
     * @param oldStr  The original string
     * @param newStr  The modified string
     * @param context Number of unchanged lines to keep around the change
     * @return A compact Unified Diff string
     */
    public static String getDiff(String oldStr, String newStr, int context) {
        // 1. Split strings into lists (required by the library)
        List<String> original = Arrays.asList(oldStr.split("\\n"));
        List<String> revised = Arrays.asList(newStr.split("\\n"));

        // 2. Compute the mathematical difference
        Patch<String> patch = DiffUtils.diff(original, revised);

        // 3. Generate the Unified Diff format
        // We use the fileName for both 'original' and 'revised' headers
        List<String> unifiedDiff = UnifiedDiffUtils.generateUnifiedDiff(
                null, null, original, patch, context);

        // Remove the first 2 lines (the --- and +++ headers)
        if (unifiedDiff.size() > 2) {
            unifiedDiff = unifiedDiff.subList(2, unifiedDiff.size());
        }

        return String.join("\n", unifiedDiff);
    }
}
