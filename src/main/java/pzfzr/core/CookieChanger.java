package pzfzr.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import burp.api.montoya.http.message.HttpHeader;

/**
 * A singleton class that stores and manages headers for different hosts.
 * Used to replace authentication-related headers in requests.
 */
public class CookieChanger {

    // Singleton instance
    private static volatile CookieChanger instance;

    // Data structure to store host -> header mappings
    // Map<host, List<HeaderEntry>> - Note: Key is now the stored pattern, not necessarily the request host
    private final Map<String, List<HeaderEntry>> hostHeadersMap;

    /**
     * Private constructor to enforce singleton pattern
     */
    private CookieChanger() {
        // Using a LinkedHashMap might be slightly better to preserve insertion order for display,
        // but HashMap is sufficient for lookup logic here.
        hostHeadersMap = new HashMap<>();
    }

    /**
     * Get the singleton instance of CookieChanger
     *
     * @return The singleton instance
     */
    public static CookieChanger getInstance() {
        if (instance == null) {
            synchronized (CookieChanger.class) {
                if (instance == null) {
                    instance = new CookieChanger();
                }
            }
        }
        return instance;
    }

    /**
     * Store a list of header entries
     *
     * @param entries List of header entries containing host pattern, header name, and header value
     */
    public void storeHeaderEntries(List<HeaderEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return;
        }

        synchronized (hostHeadersMap) {
            for (HeaderEntry entry : entries) {
                String hostPattern = entry.getHost();

                // Create list if it doesn't exist for this host pattern
                if (!hostHeadersMap.containsKey(hostPattern)) {
                    hostHeadersMap.put(hostPattern, new ArrayList<>());
                }

                // Add the entry to the host pattern's list
                // Note: This allows multiple entries for the same host pattern, which is fine.
                // If you wanted to prevent duplicates of host/headerName, you'd need more logic here.
                hostHeadersMap.get(hostPattern).add(entry);
            }
        }
    }

    /**
     * Store a single header entry
     *
     * @param entry The header entry to store
     */
    public void storeHeaderEntry(HeaderEntry entry) {
        if (entry == null) {
            return;
        }

        // Although storeHeaderEntries can handle a list, for a single entry
        // it's more direct to add it here if we want to potentially check for duplicates
        // based on host pattern + header name before adding.
        // For now, let's keep it simple and just call the list version.
        List<HeaderEntry> entries = new ArrayList<>();
        entries.add(entry);
        storeHeaderEntries(entries);
    }

    /**
     * Get HttpHeader objects that match the requested host.
     * Handles exact match and wildcard *.domain patterns.
     *
     * @param requestHost The host from the incoming HTTP request
     * @return List of HttpHeader objects that match, or null if no headers match the host or if no rules are stored
     */
    public List<HttpHeader> getHttpHeadersForHost(String requestHost) {
        if (requestHost == null || requestHost.trim().isEmpty()) {
            return null;
        }

        synchronized (hostHeadersMap) {
            // 添加这个判断：如果 map 为空，直接返回 null
            if (hostHeadersMap.isEmpty()) {
                return null;
            }

            List<HeaderEntry> matchingEntries = new ArrayList<>();

            // Iterate through all stored header entry lists
            // Note: We are iterating over the VALUES() because the KEYS are the patterns
            // and we need to check each pattern against the requestHost.
            for (List<HeaderEntry> entriesForPattern : hostHeadersMap.values()) {
                // Add a null check for the list itself, although theoretically it shouldn't be null
                // if the key exists, it's good defensive programming.
                if (entriesForPattern == null) {
                    continue; // Skip if the list is unexpectedly null
                }

                // Iterate through each individual entry within the list
                for (HeaderEntry entry : entriesForPattern) {
                    String storedHostPattern = entry.getHost();

                    // --- Matching Logic ---
                    boolean isMatch = false;
                    // Ensure stored pattern is not null or empty before attempting match
                    if (storedHostPattern != null && !storedHostPattern.trim().isEmpty()) {
                        if (storedHostPattern.startsWith("*.")) {
                            // Wildcard pattern matching: *.domain
                            String domainPart = storedHostPattern.substring(2); // Get the "domain" part after "*."
                            // Ensure the domain part is not empty after substring
                            if (!domainPart.isEmpty()) {
                                // Check if the request host ends with ".domain" AND is longer than ".domain"
                                // The length check prevents "*.example.com" from matching "example.com"
                                if (requestHost.endsWith("." + domainPart) && requestHost.length() > (domainPart.length() + 1)) {
                                    isMatch = true;
                                }
                            }
                        } else {
                            // Exact string matching
                            if (requestHost.equals(storedHostPattern)) {
                                isMatch = true;
                            }
                        }
                    }

                    if (isMatch) {
                        matchingEntries.add(entry);
                    }
                }
            }

            if (matchingEntries.isEmpty()) {
                return null; // Return null if no headers matched any rule
            }

            // Convert matched HeaderEntry objects to HttpHeader objects
            return matchingEntries.stream()
                    .map(entry -> HttpHeader.httpHeader(entry.getHeaderName(), entry.getHeaderValue()))
                    .collect(Collectors.toList());
        }
    }

    /**
     * Get all header entries for all hosts
     *
     * @return List of all header entries
     */
    public List<HeaderEntry> getAllHeaderEntries() {
        synchronized (hostHeadersMap) {
            List<HeaderEntry> allEntries = new ArrayList<>();

            // Iterate through the values (the lists of entries) in the map
            for (List<HeaderEntry> entries : hostHeadersMap.values()) {
                allEntries.addAll(entries);
            }

            return allEntries;
        }
    }

    /**
     * Update an existing header entry
     *
     * @param oldEntry The entry to be updated (identified by its original host pattern, header name, and value)
     * @param newEntry The new entry values (may include a new host pattern)
     * @return true if the entry was updated, false otherwise
     */
    public boolean updateHeaderEntry(HeaderEntry oldEntry, HeaderEntry newEntry) {
        if (oldEntry == null || newEntry == null) {
            return false;
        }

        synchronized (hostHeadersMap) {
            String oldHostPattern = oldEntry.getHost();
            String newHostPattern = newEntry.getHost();

            // Check if the old host pattern exists in the map
            if (!hostHeadersMap.containsKey(oldHostPattern)) {
                return false;
            }

            List<HeaderEntry> entriesList = hostHeadersMap.get(oldHostPattern);

            // Find the exact oldEntry in the list
            int index = -1;
            for(int i=0; i < entriesList.size(); i++){
                if(entriesList.get(i).equals(oldEntry)){ // Use the overridden equals method
                    index = i;
                    break;
                }
            }


            if (index == -1) {
                // Old entry not found in the list for its stated host pattern
                return false;
            }

            // If the host pattern has changed
            if (!oldHostPattern.equals(newHostPattern)) {
                // Remove from the old host pattern list
                entriesList.remove(index);

                // Add to the new host pattern list
                if (!hostHeadersMap.containsKey(newHostPattern)) {
                    hostHeadersMap.put(newHostPattern, new ArrayList<>());
                }
                hostHeadersMap.get(newHostPattern).add(newEntry);

                // Clean up the old list key if it becomes empty
                if (entriesList.isEmpty()) {
                    hostHeadersMap.remove(oldHostPattern);
                }

            } else {
                // Same host pattern, just update the entry in place
                entriesList.set(index, newEntry);
            }

            return true;
        }
    }


    /**
     * Delete a specific header entry
     *
     * @param entryToDelete The entry to be deleted (identified by its host pattern, header name, and value)
     * @return true if the entry was deleted, false otherwise
     */
    public boolean deleteHeaderEntry(HeaderEntry entryToDelete) {
        if (entryToDelete == null) {
            return false;
        }

        synchronized (hostHeadersMap) {
            String hostPattern = entryToDelete.getHost();

            if (!hostHeadersMap.containsKey(hostPattern)) {
                return false;
            }

            List<HeaderEntry> entriesList = hostHeadersMap.get(hostPattern);

            // Find and remove the exact entry from the list
            boolean removed = entriesList.remove(entryToDelete); // Uses the overridden equals method

            // If the list for this host pattern is now empty, remove the host pattern key
            if (entriesList.isEmpty()) {
                hostHeadersMap.remove(hostPattern);
            }

            return removed;
        }
    }


    /**
     * Clear all stored header entries
     */
    public void clearAll() {
        synchronized (hostHeadersMap) {
            hostHeadersMap.clear();
        }
    }

    /**
     * Clear header entries for a specific host pattern
     *
     * @param hostPattern The host pattern to clear entries for
     */
    public void clearHost(String hostPattern) {
        synchronized (hostHeadersMap) {
            hostHeadersMap.remove(hostPattern);
        }
    }

    /**
     * Inner class to represent a header entry with host pattern, header name, and header value
     */
    public static class HeaderEntry {
        // Renamed from 'host' to 'hostPattern' for clarity in the CookieChanger class
        private final String hostPattern;
        private final String headerName;
        private final String headerValue;

        public HeaderEntry(String hostPattern, String headerName, String headerValue) {
            this.hostPattern = hostPattern;
            this.headerName = headerName;
            this.headerValue = headerValue;
        }

        // Getter remains getHost() for compatibility with TableModel and Dialog
        public String getHost() {
            return hostPattern;
        }

        public String getHeaderName() {
            return headerName;
        }

        public String getHeaderValue() {
            return headerValue;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;

            HeaderEntry that = (HeaderEntry) obj;

            // Equality is based on all three fields
            if (!hostPattern.equals(that.hostPattern)) return false;
            if (!headerName.equals(that.headerName)) return false;
            return headerValue.equals(that.headerValue);
        }

        @Override
        public int hashCode() {
            int result = hostPattern.hashCode();
            result = 31 * result + headerName.hashCode();
            result = 31 * result + headerValue.hashCode();
            return result;
        }
    }
}