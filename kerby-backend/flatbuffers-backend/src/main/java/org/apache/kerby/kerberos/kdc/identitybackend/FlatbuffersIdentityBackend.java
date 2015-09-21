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

import com.google.flatbuffers.FlatBufferBuilder;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.kerby.util.IOUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A Flatbuffers backed backend implementation.
 *
 */
public class FlatbuffersIdentityBackend extends AbstractIdentityBackend {
    private static final Logger LOG =
            LoggerFactory.getLogger(FlatbuffersIdentityBackend.class);
    public static final String FBS_IDENTITY_BACKEND_DIR =
            "backend.flatbuffers.dir";
    private File fbsKdbFile;
    private FlatBufferBuilder fbsBuilder;
    private long kdbFileTimeStamp;

    // Identities loaded from file
    private final Map<String, KrbIdentity> identities =
        new ConcurrentHashMap<>(new TreeMap<String, KrbIdentity>());

    public FlatbuffersIdentityBackend() {

    }

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to initialize the fbs format database.
     * @param config The configuration for fbs identity backend
     */
    public FlatbuffersIdentityBackend(Config config) {
        setConfig(config);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doInitialize() throws KrbException {
        LOG.info("Initializing the Flatbuffers identity backend.");
        createFbsBuilder();
        load();
    }

    /**
     * Load identities from file
     */
    private void load() throws KrbException {
        LOG.info("Loading the identities from fbs file.");
        String fbsFile = getConfig().getString(FBS_IDENTITY_BACKEND_DIR);
        File fbsFileDir;
        if (fbsFile == null || fbsFile.isEmpty()) {
            fbsFileDir = getBackendConfig().getConfDir();
        } else {
            fbsFileDir = new File(fbsFile);
            if (!fbsFileDir.exists() && !fbsFileDir.mkdirs()) {
                throw new KrbException("could not create fbs file dir " + fbsFileDir);
            }
        }

        fbsKdbFile = new File(fbsFileDir, "fbs-backend.bin");

        if (!fbsKdbFile.exists()) {
            try {
                fbsKdbFile.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        checkAndLoad();
    }

    /**
     * Check kdb file timestamp to see if it's changed or not. If
     * necessary load the kdb again.
     */
    private synchronized void checkAndLoad() throws KrbException {
        long nowTimeStamp = fbsKdbFile.lastModified();

        if (kdbFileTimeStamp == 0 || nowTimeStamp != kdbFileTimeStamp) {
            //load identities
            String existsFbsFile = null;
            try {
                existsFbsFile = IOUtil.readFile(fbsKdbFile);
            } catch (IOException e) {
                throw new KrbException("Failed to read file", e);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(String principalName) throws KrbException {
        checkAndLoad();
        return identities.get(principalName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) throws KrbException {
        checkAndLoad();

        identities.put(identity.getPrincipalName(), identity);
        idsToFile(identities);

        return doGetIdentity(identity.getPrincipalName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) throws KrbException {
        checkAndLoad();
        identities.put(identity.getPrincipalName(), identity);
        idsToFile(identities);

        return doGetIdentity(identity.getPrincipalName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) throws KrbException {
        checkAndLoad();
        if (identities.containsKey(principalName)) {
            identities.remove(principalName);
        }
        idsToFile(identities);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Iterable<String> doGetIdentities() throws KrbException {
        List<String> principals = new ArrayList<>(identities.keySet());
        Collections.sort(principals);

        return principals;
    }

    private void createFbsBuilder() {
        fbsBuilder = new FlatBufferBuilder();
    }

    /**
     * Write identities into a file
     * @param ids the identities to write into the fbs file
     */
    private synchronized void idsToFile(Map<String, KrbIdentity> ids) throws KrbException {
        String newFbsFile = null;
        try {
            IOUtil.writeFile(newFbsFile, fbsKdbFile);
        } catch (IOException e) {
            LOG.error("Error occurred while writing identities to file: " + fbsKdbFile);
            throw new KrbException("Failed to write file", e);
        }
    }
}
