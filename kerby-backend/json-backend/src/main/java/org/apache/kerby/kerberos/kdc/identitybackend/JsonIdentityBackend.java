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
package org.apache.kerby.kerberos.kdc.identitybackend;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter.EncryptionKeyAdapter;
import org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter.KerberosTimeAdapter;
import org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter.PrincipalNameAdapter;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.BatchTrans;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.util.IOUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A Json file based backend implementation.
 */
public class JsonIdentityBackend extends AbstractIdentityBackend {
    private static final Logger LOG =
            LoggerFactory.getLogger(JsonIdentityBackend.class);

    public static final String JSON_IDENTITY_BACKEND_DIR = "backend.json.dir";
    private File jsonKdbFile;
    private Gson gson;

    // Identities loaded from file
    private final Map<String, KrbIdentity> identities =
        new ConcurrentHashMap<>(new TreeMap<String, KrbIdentity>());
    private long kdbFileUpdateTime = -1;

    private Lock lock = new ReentrantLock();

    public JsonIdentityBackend() {

    }

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to initialize the json format database.
     * @param config The configuration for json identity backend
     */
    public JsonIdentityBackend(Config config) {
        setConfig(config);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supportBatchTrans() {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public BatchTrans startBatchTrans() throws KrbException {
        if (lock.tryLock()) {
            checkAndReload();
            return new JsonBatchTrans();
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doInitialize() throws KrbException {
        LOG.info("Initializing the Json identity backend.");

        initGsonBuilder();

        String dirPath = getConfig().getString(JSON_IDENTITY_BACKEND_DIR);
        File jsonFileDir;
        if (dirPath == null || dirPath.isEmpty()) {
            jsonFileDir = getBackendConfig().getConfDir();
        } else {
            jsonFileDir = new File(dirPath);
            if (!jsonFileDir.exists() && !jsonFileDir.mkdirs()) {
                throw new KrbException("Failed to create json file dir " + jsonFileDir);
            }
        }

        jsonKdbFile = new File(jsonFileDir, "json-backend.json");
        if (!jsonKdbFile.exists()) {
            try {
                jsonKdbFile.createNewFile();
            } catch (IOException e) {
                throw new KrbException("Failed to create " + jsonKdbFile.getAbsolutePath());
            }
        }
    }

    private void load() throws KrbException {
        LOG.info("Loading the identities from json file.");

        long nowTimeStamp = jsonKdbFile.lastModified();
        String reloadedJsonContent;
        if (lock.tryLock()) {
            try {
                try {
                    reloadedJsonContent = IOUtil.readFile(jsonKdbFile);
                } catch (IOException e) {
                    throw new KrbException("Failed to read file", e);
                }

                Map<String, KrbIdentity> reloadedEntries =
                        gson.fromJson(reloadedJsonContent,
                                new TypeToken<HashMap<String, KrbIdentity>>() {
                                }.getType());

                if (reloadedEntries != null) {
                    identities.clear();
                    identities.putAll(reloadedEntries);
                }

                kdbFileUpdateTime = nowTimeStamp;
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * Check kdb file timestamp to see if it's changed or not. If
     * necessary load the kdb again.
     */
    private void checkAndReload() throws KrbException {
        long nowTimeStamp = jsonKdbFile.lastModified();
        if (nowTimeStamp != kdbFileUpdateTime) {
            load();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(String principalName) throws KrbException {
        checkAndReload();
        return identities.get(principalName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) throws KrbException {
        checkAndReload();

        if (lock.tryLock()) {
            try {
                identities.put(identity.getPrincipalName(), identity);
                persistToFile();
            } finally {
                lock.unlock();
            }
        }

        return doGetIdentity(identity.getPrincipalName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) throws KrbException {
        checkAndReload();

        if (lock.tryLock()) {
            try {
                identities.put(identity.getPrincipalName(), identity);
                persistToFile();
            } finally {
                lock.unlock();
            }
        }

        return doGetIdentity(identity.getPrincipalName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) throws KrbException {
        checkAndReload();

        if (!identities.containsKey(principalName)) {
            return;
        }

        if (lock.tryLock()) {
            try {
                identities.remove(principalName);
                persistToFile();
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Iterable<String> doGetIdentities() throws KrbException {
        load();
        List<String> principals = new ArrayList<>(identities.keySet());
        Collections.sort(principals);

        return principals;
    }

    private void initGsonBuilder() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(EncryptionKey.class, new EncryptionKeyAdapter());
        gsonBuilder.registerTypeAdapter(PrincipalName.class, new PrincipalNameAdapter());
        gsonBuilder.registerTypeAdapter(KerberosTime.class, new KerberosTimeAdapter());
        gsonBuilder.enableComplexMapKeySerialization();
        gsonBuilder.setPrettyPrinting();
        gson = gsonBuilder.create();
    }

    private void persistToFile() throws KrbException {
        String newJsonContent = gson.toJson(identities);
        try {
            File newJsonKdbFile = File.createTempFile("kerby-kdb",
                    ".json", jsonKdbFile.getParentFile());
            IOUtil.writeFile(newJsonContent, newJsonKdbFile);
            boolean delete = jsonKdbFile.delete();
            if (!delete) {
                throw new RuntimeException("File delete error!");
            }
            boolean rename = newJsonKdbFile.renameTo(jsonKdbFile);
            if (!rename) {
                throw new RuntimeException("File rename error!");
            }
            kdbFileUpdateTime = jsonKdbFile.lastModified();
        } catch (IOException e) {
            LOG.error("Error occurred while writing identities to file: " + jsonKdbFile);
            throw new KrbException("Failed to write file", e);
        }
    }

    class JsonBatchTrans implements BatchTrans {

        @Override
        public void commit() throws KrbException {
            try {
                // Force to persist memory states to disk file.
                persistToFile();
            } finally {
                lock.unlock();
            }
        }

        @Override
        public void rollback() throws KrbException {
            // Force to reload from disk file and disgard the memory states.
            try {
                load();
            } finally {
                lock.unlock();
            }
        }

        @Override
        public BatchTrans addIdentity(KrbIdentity identity) throws KrbException {
            if (identity != null
                    && identities.containsKey(identity.getPrincipalName())) {
                identities.put(identity.getPrincipalName(), identity);
            }
            return this;
        }

        @Override
        public BatchTrans updateIdentity(KrbIdentity identity) throws KrbException {
            if (identity != null
                    && identities.containsKey(identity.getPrincipalName())) {
                identities.put(identity.getPrincipalName(), identity);
            }
            return this;
        }

        @Override
        public BatchTrans deleteIdentity(String principalName) throws KrbException {
            if (principalName != null && identities.containsKey(principalName)) {
                identities.remove(principalName);
            }
            return this;
        }
    }
}
