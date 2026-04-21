/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * This class reads and parses provider service definitions from a file.
 * 
 * This class reads files containing putService() calls in the format:
 * putService(new OpenJCEPlusService(provider, "Type", "Algorithm",
 * "ClassName", aliases));
 * 
 * Example usage:
 * <pre>
 * ProviderServiceReader reader = new ProviderServiceReader("services.txt");
 * List<ServiceDefinition> services = reader.readServices();
 * for (ServiceDefinition service : services) {
 *     System.out.println(service.getType() + ": " + 
 *                        service.getAlgorithm());
 * }
 * </pre>
 */
public class ProviderServiceReader {

    private BufferedReader reader = null;
    private String filePath = null;
    private String name;
    private String description;
    private String backend;  // Backend selector: "OCK" or "OpenSSL"
    private List<ServiceDefinition> cachedServices = null;

    /**
     * Represents a single service definition parsed from the file.
     */
    public static class ServiceDefinition {
        private final String type;
        private final String algorithm;
        private final String className;
        private final List<String> aliases;
        private final Map<String, String> attributes;

        public ServiceDefinition(String type, String algorithm, 
                String className, List<String> aliases, Map<String, String> attributes) {
            this.type = type;
            this.algorithm = algorithm;
            this.className = className;
            this.aliases = aliases != null ? new ArrayList<>(aliases) : new ArrayList<>();
            this.attributes = attributes != null ? new HashMap<>(attributes) : new HashMap<>();
        }

        public String getType() {
            return type;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public String getClassName() {
            return className;
        }

        public List<String> getAliases() {
            return new ArrayList<>(aliases);
        }

        public Map<String, String> getAttributes() {
            return new HashMap<>(attributes);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("ServiceDefinition(")
              .append(", type=").append(type)
              .append(", algorithm=").append(algorithm)
              .append(", className=").append(className);
            if (!aliases.isEmpty()) {
                sb.append(", aliases=").append(aliases);
            }
            if (!attributes.isEmpty()) {
                sb.append(", attributes=").append(attributes);
            }
            sb.append(")");
            return sb.toString();
        }
    }

    /**
     * Creates a new ProviderServiceReader for the specified file.
     * 
     * @param filePath the path to the file containing service definitions
     */
    public ProviderServiceReader(String filePath) throws IOException {
        this.filePath = filePath;
        parseAll();
    }

    /**
     * Creates a new ProviderServiceReader for the specified BufferedReader.
     *
     * @param br the BufferedReader containing service definitions
     */
    public ProviderServiceReader(BufferedReader br) throws IOException {
        this.reader = br;
        parseAll();
    }

    /**
     * Parse everything (metadata and services) from the configuration.
     * This is called in the constructor so getName(), getDesc(), getBackend(),
     * and readServices() all work correctly.
     */
    private void parseAll() throws IOException {
        cachedServices = readServicesInternal();
    }

    /**
     * Reads and parses all service definitions from the file.
     * Returns cached services that were parsed in the constructor.
     *
     * @return a list of ServiceDefinition objects
     */
    public List<ServiceDefinition> readServices() {
        // Return cached services that were parsed in constructor
        return new ArrayList<>(cachedServices);
    }

    /**
     * Internal method that actually parses the services from the configuration.
     * This is called once in the constructor and the results are cached.
     *
     * @return a list of ServiceDefinition objects
     * @throws IOException if an I/O error occurs
     */
    private List<ServiceDefinition> readServicesInternal() throws IOException {
        Set<String> setAttributes = new HashSet<>();
        Set<String> setServices = new HashSet<>();
        BufferedReader rd = null;
        Properties pr = new Properties();

        try {
            if (filePath == null && this.reader == null) {
                throw new IOException("No file specified");
            } else if (null == filePath && this.reader != null) {
                rd = this.reader;
            } else {
                // this filePath != null &&
                if (!Files.exists(Paths.get(filePath))) {
                    throw new IOException("File not found: " + filePath);
                } else {
                    // this filePath != null &&
                    // !Files.exists(Paths.get(filePath))
                    rd = new BufferedReader(new FileReader(filePath));
                }
            }

            pr.load(rd);

            Set<String> keys = pr.stringPropertyNames();

            for (String key : keys) {
                String[] parts = key.split("\\.", 4); // Split into max 4 parts
                if (parts.length >= 3 &&
                    parts[0].equalsIgnoreCase("Service")) {
                    // Service.Type.Algorithm (algorithm may contain dots or hyphens)
                    if (parts.length == 3) {
                        setServices.add(key);
                    } else if (parts.length == 4) {
                        // Could be Service.Type.alias.Algorithm or Service.Type.attr.Algorithm
                        String[] subParts = parts[2].split("\\.", 2);
                        if (subParts.length >= 1) {
                            if (subParts[0].equalsIgnoreCase("alias")) {
                                // Alias keys are not added to setServices
                            } else if (subParts[0].equalsIgnoreCase("attr")) {
                                setAttributes.add(key);
                            } else {
                                // It's a service with dots in the algorithm name
                                setServices.add(key);
                            }
                        }
                    }
                } else if (parts.length == 1) {
                    if (parts[0].equalsIgnoreCase("name")) {
                        name = pr.getProperty(key);
                    } else if (parts[0].equalsIgnoreCase("description")) {
                        description = pr.getProperty(key);
                    } else if (parts[0].equalsIgnoreCase("backend")) {
                        backend = pr.getProperty(key);
                    } else {
                        throw new IOException("Invalid key: " + key);
                    }
                } else {
                    throw new IOException("Invalid key: " + key);
                }
            }

            // Metadata was already parsed in constructor
            List<ServiceDefinition> services = new ArrayList<>();

            for (String serviceKey : setServices) {
                // Split into Service.Type.Algorithm where Algorithm may contain dots
                String[] parts = serviceKey.split("\\.", 3);
                if (parts.length < 3) {
                    continue; // Skip invalid keys
                }
                String type = parts[1];
                String algorithm = parts[2];
                String className = pr.getProperty(serviceKey);

                // Get aliases
                List<String> aliases = new ArrayList<>();
                int aliasIndex = 0;
                while (true) {
                    String aliasKey = "Service." + type + ".alias." +
                                     algorithm + "." + aliasIndex;
                    String alias = pr.getProperty(aliasKey);
                    if (alias == null) {
                        break;
                    }
                    aliases.add(alias);
                    aliasIndex++;
                }

                // Get attributes
                Map<String, String> attributes = new HashMap<>();
                for (String attrKey : setAttributes) {
                    // Split into Service.Type.attr.Algorithm.AttrName
                    String[] attrParts = attrKey.split("\\.", 5);
                    if (attrParts.length >= 5 &&
                        attrParts[1].equals(type) &&
                        attrParts[2].equalsIgnoreCase("attr")) {
                        // Extract algorithm and attribute name
                        String attrAlgorithm = attrKey.substring(
                            ("Service." + type + ".attr.").length(),
                            attrKey.lastIndexOf('.')
                        );
                        if (attrAlgorithm.equals(algorithm)) {
                            String attrName = attrParts[attrParts.length - 1];
                            String attrValue = pr.getProperty(attrKey);
                            attributes.put(attrName, attrValue);
                        }
                    }
                }

                services.add(new ServiceDefinition(type, algorithm,
                                                   className, aliases, attributes));
            }

            return services;

        } finally {
            if (rd != null && filePath != null) {
                rd.close();
            }
        }
    }

    /**
     * Gets the provider name from the configuration.
     * 
     * @return the provider name
     */
    public String getName() {
        return name;
    }

    /**
     * Gets the provider description from the configuration.
     * 
     * @return the provider description
     */
    public String getDesc() {
        return description;
    }

    /**
     * Gets the backend selector from the configuration.
     * 
     * @return the backend name ("OCK" or "OpenSSL")
     */
    public String getBackend() {
        return backend;
    }
}


