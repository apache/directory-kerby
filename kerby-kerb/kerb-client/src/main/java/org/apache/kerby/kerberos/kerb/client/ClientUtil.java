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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.kerberos.kerb.KrbException;

import java.io.File;
import java.io.IOException;
import java.util.Map;

public final class ClientUtil {
    private ClientUtil() {}

    private final static String krb5FileName = "krb5.conf";
    private final static String krb5EnvName = "KRB5_CONFIG";

    /**
     * Load krb5.conf from specified conf dir.
     */
    public static KrbConfig getConfig(File confDir) throws KrbException {
        File confFile = new File(confDir, krb5FileName);
        if (!confFile.exists()) {
            throw new KrbException(krb5FileName + " not found");
        }

        if (confFile != null && confFile.exists()) {
            KrbConfig krbConfig = new KrbConfig();
            try {
                krbConfig.addIniConfig(confFile);
                return krbConfig;
            } catch (IOException e) {
                throw new KrbException("Failed to load krb config " + confFile.getAbsolutePath());
            }
        }

        return null;
    }

    /**
     * Load default krb5.conf
     */
    public static KrbConfig getDefaultConfig() throws KrbException {
        File confFile = null;
        File confDir;
        String tmpEnv;

        try {
            Map<String, String> mapEnv = System.getenv();
            tmpEnv = mapEnv.get(krb5EnvName);
        } catch (SecurityException e) {
            tmpEnv = null;
        }
        if (tmpEnv != null) {
            confFile = new File(tmpEnv);
            if (!confFile.exists()) {
                throw new KrbException("krb5 conf not found. Invalid env " + krb5EnvName);
            }
        } else {
            confDir = new File("/etc/"); // for Linux. TODO: fix for Win etc.
            if (confDir.exists()) {
                confFile = new File(confDir, "krb5.conf");
            }
        }

        if (confFile != null && confFile.exists()) {
            KrbConfig krbConfig = new KrbConfig();
            try {
                krbConfig.addIniConfig(confFile);
                return krbConfig;
            } catch (IOException e) {
                throw new KrbException("Failed to load krb config " + confFile.getAbsolutePath());
            }
        }

        return null;
    }
}
