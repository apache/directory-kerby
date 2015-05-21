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
import org.apache.kerby.kerberos.kdc.identitybackend.tool.FileHelper;
import org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter.EncryptionKeyAdapter;
import org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter.KerberosTimeAdapter;
import org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter.PrincipalNameAdapter;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

/**
 * A Json file based backend implementation.
 *
 */
public class JsonIdentityBackend extends AbstractIdentityBackend {
    public static final String JSON_IDENTITY_BACKEND_FILE = "backend.json.file";
    private File jsonKdbFile;
    private Gson gson;

    /**
     * Identities loaded from file
     */
    private Map<String, KrbIdentity> ids;
    private long kdbFileTimeStamp;

    public JsonIdentityBackend() {
    }

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to initialize the json format database.
     * @param config
     */
    public JsonIdentityBackend(Config config) {
        setConfig(config);
    }

    @Override
    public void initialize() {
        super.initialize();
        createGson();
        load();
    }

    /**
     * Load identities from file
     */
    public void load() {
        String jsonFile = getConfig().getString(JSON_IDENTITY_BACKEND_FILE);
        if (jsonFile == null || jsonFile.isEmpty()) {
            throw new RuntimeException("No json kdb file is found");
        }

        jsonKdbFile = new File(jsonFile);
        if (! jsonKdbFile.exists()) {
            try {
                jsonKdbFile.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        checkAndLoad();
    }

    /**
     * check kdb file timestamp to see if it's changed or not. If
     * necessary load the kdb again.
     */
    private void checkAndLoad() {
        long nowTimeStamp = jsonKdbFile.lastModified();

        if (kdbFileTimeStamp == 0 || nowTimeStamp != kdbFileTimeStamp) {
            //load ids
            String existsFileJson = FileHelper.readFromFile(jsonKdbFile);

            ids = gson.fromJson(existsFileJson,
                    new TypeToken<LinkedHashMap<String, KrbIdentity>>() {
                    }.getType());
        }

        if (ids == null) {
            ids = new LinkedHashMap<>();
        }
    }

    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
        checkAndLoad();
        return ids.get(principalName);
    }

    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        checkAndLoad();

        String principal = identity.getPrincipalName();
        if (ids.containsKey(principal)) {
            throw new RuntimeException("Principal already exists.");
        }

        ids.put(identity.getPrincipalName(), identity);
        idsToFile(ids);

        return identity;
    }

    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        checkAndLoad();
        if (ids.containsKey(identity.getPrincipalName())) {
            ids.put(identity.getPrincipalName(), identity);
        } else {
            throw new RuntimeException("Principal does not exist.");
        }
        idsToFile(ids);
        return identity;
    }

    @Override
    protected void doDeleteIdentity(String principalName) {
        checkAndLoad();
        if (ids.containsKey(principalName)) {
            ids.remove(principalName);
        } else {
            throw new RuntimeException("Principal does not exist.");
        }
        idsToFile(ids);
    }

    @Override
    public List<String> getIdentities(int start, int limit) {
        LinkedHashMap<String, KrbIdentity> linkedIds = (LinkedHashMap<String, KrbIdentity>) ids;
        Iterator<Entry<String, KrbIdentity>> iterator = linkedIds.entrySet().iterator();

        int index = 0;
        for(; index < start; index++) {
            iterator.next();
        }

        List<String> principals = new ArrayList<>();
        for (; index < limit; index++) {
            Entry<String, KrbIdentity> entry = iterator.next();
            principals.add(entry.getKey());
        }

        return principals;
    }

    @Override
    public List<String> getIdentities() {
        List<String> principals = new ArrayList<>(ids.keySet());
        Collections.sort(principals);

        return principals;
    }

    private void createGson() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(EncryptionKey.class, new EncryptionKeyAdapter());
        gsonBuilder.registerTypeAdapter(PrincipalName.class, new PrincipalNameAdapter());
        gsonBuilder.registerTypeAdapter(KerberosTime.class, new KerberosTimeAdapter());
        gsonBuilder.enableComplexMapKeySerialization();
        gsonBuilder.setPrettyPrinting();
        gson = gsonBuilder.create();
    }

    private void idsToFile(Map<String, KrbIdentity> ids) {
        String newFileJson = gson.toJson(ids);
        FileHelper.writeToFile(newFileJson, jsonKdbFile);
    }


}
