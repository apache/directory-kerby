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

import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.InMemoryIdentityBackend;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * An Json file based backend implementation.
 *
 */
public class JsonIdentityBackend extends InMemoryIdentityBackend {
    public static final String JSON_IDENTITY_BACKEND_FILE =
            "kdc.identitybackend.json.file";
    private Config config;
    private File jsonKdbFile;

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to initialize the json format database.
     * @param config
     */
    public JsonIdentityBackend(Config config) {
        this.config = config;
    }

    /**
     * Load identities from file
     */
    public void load() throws IOException {
        String jsonFile = config.getString(JSON_IDENTITY_BACKEND_FILE);
        if (jsonFile == null || jsonFile.isEmpty()) {
            throw new RuntimeException("No json kdb file is found");
        }

        jsonKdbFile = new File(jsonFile);
        if (! jsonKdbFile.exists()) {
            throw new FileNotFoundException("File not found:" + jsonFile);
        }

        // TODO: load the kdb file.
    }

    private void checkAndLoad() {
        // TODO: check kdb file timestamp to see if it's changed or not. If
        // necessary load the kdb again.
    }

    /**
     * Persist the updated identities back
     */
    public void save() {
        // TODO: save into the kdb file
    }

    @Override
    public KrbIdentity getIdentity(String name) {
        return super.getIdentity(name);
    }

    @Override
    public void addIdentity(KrbIdentity identity) {
        super.addIdentity(identity);

        // TODO: save
    }

    @Override
    public void updateIdentity(KrbIdentity identity) {
        super.updateIdentity(identity);

        // TODO: save
    }

    @Override
    public void deleteIdentity(KrbIdentity identity) {
        super.deleteIdentity(identity);

        // TODO: save
    }
}
