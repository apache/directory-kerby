/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.common;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * A parser to parse krb5.conf format file.
 */
public class Krb5Parser {
    private File krb5conf;
    /**
     * The variable items regards section name as a key of Map, and
     * contents of a section as a value with Object type.
     * In specific, the value is a recursive Map type, which can be
     * in the form of both Map<String, String> and Map<String, Object>,
     * depending on contents of the section.
     */
    private Map<String, Object> items;

    public Krb5Parser(File confFile) {
        krb5conf = confFile;
        items = null;
    }

    /**
     * Load the krb5.conf into a member variable, which is a Map.
     * @throws IOException e
     */
    public void load() throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(krb5conf),
                StandardCharsets.UTF_8));
        items = new IdentityHashMap<>();

        String originLine = br.readLine();
        while (originLine != null) {
            String line = originLine.trim();
            /*parse through comments*/
            if (line.startsWith("#") || line.length() == 0) {
                originLine = br.readLine();
            }   else if (line.startsWith("[")) {
                insertSections(line, br, items);
                originLine = br.readLine();
            }   else {
                throw new RuntimeException("Unable to parse:" + originLine);
            }
        }
        br.close();
    }

    /**
     * Get the whole map.
     * @return member variable items.
     */
    public Map<String, Object> getItems() {
        return items;
    }



    /**
     * Get all the names of sections in a list.
     * @return a list of section names.
     */
    public List<String> getSections() {
        List<String> al = new ArrayList<String>(items.keySet());
        return al;
    }

    /**
     * Get the contents of a section given the section name.
     * @param sectionName the name of a section
     * @param keys the keys list
     * @return a Map of section contents
     */
    public Object getSection(String sectionName, String ... keys) {
        Object value = null;
        for (Map.Entry<String, Object> item : items.entrySet()) {
            if (item.getKey().equals(sectionName)) {
                value = item.getValue();
                Map<String, Object> map = (Map) item.getValue();
                for (Map.Entry<String, Object> entry : map.entrySet()) {
                    if (entry.getKey().equals(keys[0])) {
                        value = entry.getValue();
                    }
                }
            }
        }

        for (int i = 1; i < keys.length; i++) {
            Map<String, Object> map = (Map) value;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (entry.getKey().equals(keys[i])) {
                    value = entry.getValue();
                }
            }
        }
        return value;
    }

    /**
     * Print all the meaningful contents of the krb5.conf on the console.
     * Comments are ignored.
     * Hierarchy is considered.
     * Attention that the order of sections and the order inside a section
     * will be different to the original file, due to the use of HashMap.
     */
    public void dump() {
        printSection(items);
    }

    private void insertSections(String line, BufferedReader br, Map<String, Object> items) throws IOException {
        while (line.startsWith("[")) {
            String sectionName = line.substring(1, line.length() - 1);
            Map<String, Object> entries = new IdentityHashMap<>();
            line = br.readLine();
            if (line == null) {
                break;
            }
            while (line.startsWith("#")) {
                line = br.readLine();
                if (line == null) {
                    break;
                }
            }
            if (line != null) {
                line = line.trim();
                line = insertEntries(line, br, entries);
                items.put(sectionName, entries);
            }
            /*line has been modified after the recursive.*/
            if (line == null) {
                /*the end of file*/
                break;
            }
        }
    }

    /**
     * recursively go through the key-value pairs of a section
     * */
    private String insertEntries(String line, BufferedReader br, Map<String, Object> entries) throws IOException {
        if (line == null) {
            return line;
        }
        if (line.startsWith("[")) {
            return line;
        }

        if (line.startsWith("}")) {
            line = br.readLine();
            if (line != null) {
                line = line.trim();
            }
            return line;
        }
        if (line.length() == 0 || line.startsWith("#")) {
            line = br.readLine();
            if (line != null) {
                line = line.trim();
                line = insertEntries(line, br, entries);
            }
            return line;
        }
        /*some special cases above*/
        String[] kv = line.split("=", 2);
        kv[0] = kv[0].trim();
        kv[1] = kv[1].trim();

        if (kv[1].startsWith("{")) {
            Map<String, Object> meValue = new IdentityHashMap<>();
            line = br.readLine();
            if (line != null) {
                line = line.trim();
                line = insertEntries(line, br, meValue);
                entries.put(kv[0], meValue);
                line = insertEntries(line, br, entries);
            }
        }   else {
            entries.put(kv[0], kv[1]);
            line = br.readLine();
            if (line != null) {
                line = line.trim();
                line = insertEntries(line, br, entries);
            }
        }
        return line;
    }

    private void printSection(Map<String, Object> map) {
        Iterator iter = map.entrySet().iterator();
        while (iter.hasNext()) {
            Map.Entry entry = (Map.Entry) iter.next();
            String key = (String) entry.getKey();
            Object value = entry.getValue();
            System.out.println("[" + key + "]");

            if (value instanceof Map) {
                int count = 0;
                printEntry((Map) value, count);
            }   else {
                throw new RuntimeException("Unable to print contents of [" + key + "]");
            }
        }
    }

    private void printEntry(Map<String, Object> map, int count) {
        Iterator iter = map.entrySet().iterator();
        while (iter.hasNext()) {
            Map.Entry entry = (Map.Entry) iter.next();
            String key = (String) entry.getKey();
            Object value = entry.getValue();
            for (int i = 0; i < count; i++) {
                System.out.print("\t");
            }
            if (value instanceof String) {
                System.out.println(key + " = " + (String) value);
            }
            if (value instanceof Map) {
                System.out.println(key + " = {");
                printEntry((Map) value, count + 1);
                for (int i = 0; i < count; i++) {
                    System.out.print("\t");
                }
                System.out.println("}");
            }
        }
    }
}