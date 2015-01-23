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
package org.apache.kerby.kerberos.kerb.keytab;

import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;

public class Keytab implements KrbKeytab {

    public static final int V501 = 0x0501;
    public static final int V502 = 0x0502;

    private int version = V502;

    private Map<PrincipalName, List<KeytabEntry>> principalEntries;

    public Keytab() {
        this.principalEntries = new HashMap<PrincipalName, List<KeytabEntry>>();
    }

    @Override
    public List<PrincipalName> getPrincipals() {
        return new ArrayList<PrincipalName>(principalEntries.keySet());
    }

    @Override
    public void addKeytabEntries(List<KeytabEntry> entries) {
        for (KeytabEntry entry : entries) {
            addEntry(entry);
        }
    }

    @Override
    public void removeKeytabEntries(PrincipalName principal) {
        principalEntries.remove(principal);
    }

    @Override
    public void removeKeytabEntry(KeytabEntry entry) {
        PrincipalName principal = entry.getPrincipal();
        List<KeytabEntry> entries = principalEntries.get(principal);
        if (entries != null) {
            Iterator<KeytabEntry> iter = entries.iterator();
            KeytabEntry tmp;
            while (iter.hasNext()) {
                tmp = iter.next();
                if (entry.equals(tmp)) {
                    iter.remove();
                    break;
                }
            }
        }
    }

    @Override
    public List<KeytabEntry> getKeytabEntries(PrincipalName principal) {
        return principalEntries.get(principal);
    }

    @Override
    public EncryptionKey getKey(PrincipalName principal, EncryptionType keyType) {
        List<KeytabEntry> entries = getKeytabEntries(principal);
        for (KeytabEntry ke : entries) {
            if (ke.getKey().getKeyType() == keyType) {
                return ke.getKey();
            }
        }

        return null;
    }

    @Override
    public void load(File keytabFile) throws IOException {
        if (! keytabFile.exists() || ! keytabFile.canRead()) {
            throw new IllegalArgumentException("Invalid keytab file: " + keytabFile.getAbsolutePath());
        }

        InputStream is = new FileInputStream(keytabFile);

        load(is);
    }

    @Override
    public void load(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            throw new IllegalArgumentException("Invalid and null input stream");
        }

        KeytabInputStream kis = new KeytabInputStream(inputStream);

        doLoad(kis);
    }

    private void doLoad(KeytabInputStream kis) throws IOException {
        this.version = readVersion(kis);

        List<KeytabEntry> entries = readEntries(kis);
        addKeytabEntries(entries);
    }

    @Override
    public void addEntry(KeytabEntry entry) {
        PrincipalName principal = entry.getPrincipal();
        List<KeytabEntry> entries = principalEntries.get(principal);
        if (entries == null) {
            entries = new ArrayList<KeytabEntry>();
            principalEntries.put(principal, entries);
        }
        entries.add(entry);
    }

    private int readVersion(KeytabInputStream kis) throws IOException {
        return kis.readShort();
    }

    private List<KeytabEntry> readEntries(KeytabInputStream kis) throws IOException {
        List<KeytabEntry> entries = new ArrayList<KeytabEntry>();

        int entrySize;
        ByteBuffer entryData;
        KeytabEntry entry;
        while (kis.available() > 0) {
            entrySize = kis.readInt();
            if (kis.available() < entrySize) {
                throw new IOException("Bad input stream with less data than expected: " + entrySize);
            }
            entry = readEntry(kis);
            entries.add(entry);
        }

        return entries;
    }

    private KeytabEntry readEntry(KeytabInputStream kis) throws IOException {
        KeytabEntry entry = new KeytabEntry();
        entry.load(kis, version);
        return entry;
    }

    @Override
    public void store(File keytabFile) throws IOException {
        OutputStream outputStream = new FileOutputStream(keytabFile);

        store(outputStream);
    }

    @Override
    public void store(OutputStream outputStream) throws IOException {
        if (outputStream == null) {
            throw new IllegalArgumentException("Invalid and null output stream");
        }

        KeytabOutputStream kos = new KeytabOutputStream(outputStream);

        writeVersion(kos);
        writeEntries(kos);
    }

    private void writeVersion(KeytabOutputStream kos) throws IOException {
        byte[] bytes = new byte[2];
        bytes[0] = (byte) 0x05;
        bytes[1] = version == V502 ? (byte) 0x02 : (byte) 0x01;

        kos.write(bytes);
    }

    private void writeEntries(KeytabOutputStream kos) throws IOException {
        for (PrincipalName principal : principalEntries.keySet()) {
            for (KeytabEntry entry : principalEntries.get(principal)) {
                entry.store(kos);
            }
        }
    }

}
