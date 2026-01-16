package com.lauriewired.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Utility class for JSON parsing using Gson.
 * Replaces manual JSON parsing with a robust library implementation.
 */
public class JsonUtils {

    private static final Gson GSON = new GsonBuilder().create();

    /**
     * Parse a JSON array of objects into a list of string maps.
     * Example input: [{"key1":"val1"},{"key1":"val2"}]
     *
     * @param json JSON array string
     * @return List of maps, or empty list if null/invalid
     */
    public static List<Map<String, String>> parseJsonArray(String json) {
        if (json == null || json.isEmpty()) {
            return Collections.emptyList();
        }
        try {
            Type type = new TypeToken<List<Map<String, String>>>() {}.getType();
            List<Map<String, String>> result = GSON.fromJson(json, type);
            return result != null ? result : Collections.emptyList();
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    /**
     * Parse a JSON object into a string map.
     * Example input: {"key1":"val1","key2":"val2"}
     *
     * @param json JSON object string
     * @return Map of strings, or empty map if null/invalid
     */
    public static Map<String, String> parseJsonObject(String json) {
        if (json == null || json.isEmpty()) {
            return Collections.emptyMap();
        }
        try {
            Type type = new TypeToken<Map<String, String>>() {}.getType();
            Map<String, String> result = GSON.fromJson(json, type);
            return result != null ? result : Collections.emptyMap();
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    /**
     * Parse a JSON object deeply (supports nested objects and arrays).
     * Example input: {"key1":"val1","nested":{"a":1},"list":[1,2,3]}
     *
     * @param json JSON object string
     * @return Map with Object values (can contain nested Maps and Lists)
     */
    public static Map<String, Object> parseJsonObjectDeep(String json) {
        if (json == null || json.isEmpty()) {
            return Collections.emptyMap();
        }
        try {
            Type type = new TypeToken<Map<String, Object>>() {}.getType();
            Map<String, Object> result = GSON.fromJson(json, type);
            return result != null ? result : Collections.emptyMap();
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    /**
     * Parse a JSON array of strings.
     * Example input: ["val1","val2","val3"]
     *
     * @param json JSON array string
     * @return List of strings, or empty list if null/invalid
     */
    public static List<String> parseJsonStringArray(String json) {
        if (json == null || json.isEmpty()) {
            return Collections.emptyList();
        }
        try {
            Type type = new TypeToken<List<String>>() {}.getType();
            List<String> result = GSON.fromJson(json, type);
            return result != null ? result : Collections.emptyList();
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    /**
     * Convert an object to JSON string.
     *
     * @param obj Object to serialize
     * @return JSON string representation
     */
    public static String toJson(Object obj) {
        return GSON.toJson(obj);
    }
}
