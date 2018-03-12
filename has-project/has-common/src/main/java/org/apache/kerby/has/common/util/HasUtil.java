/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kerby.has.common.util;

import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;

public class HasUtil {

    /**
     * Get has configuration
     * @param hasConfFile configuration directory
     * @return has configuration
     */
    public static HasConfig getHasConfig(File hasConfFile) throws HasException {

        if (hasConfFile.exists()) {
            HasConfig hasConfig = new HasConfig();
            try {
                hasConfig.addIniConfig(hasConfFile);
            } catch (IOException e) {
                throw new HasException("Can not load the has configuration file "
                    + hasConfFile.getAbsolutePath());
            }
            return hasConfig;
        } else {
            throw new HasException(hasConfFile.getName() + "not found in "
                + hasConfFile.getParent() + ". ");
        }
    }

    public static void setEnableConf(File hasConfFile, String value)
            throws HasException, IOException {
        String oldValue = getHasConfig(hasConfFile).getEnableConf();
        if (oldValue == null) {
            throw new HasException("Please set enable_conf in has-server.conf.");
        }
        if (oldValue.equals(value)) {
            return;
        }
        try {
            BufferedReader bf = new BufferedReader(new FileReader(hasConfFile));
            StringBuilder sb = new StringBuilder();
            String tempString;
            while ((tempString = bf.readLine()) != null) {
                if (tempString.trim().startsWith("enable_conf")) {
                    tempString = tempString.replace(oldValue, value);
                }
                sb.append(tempString + "\n");
            }
            try (PrintStream ps = new PrintStream(new FileOutputStream(hasConfFile))) {
                ps.print(sb.toString());
                bf.close();
            }
        } catch (FileNotFoundException e) {
            throw new HasException("Can not load the has configuration file "
                    + hasConfFile.getAbsolutePath());
        }
    }

    public static EncryptionKey getClientKey(String userName, String passPhrase,
                                             EncryptionType type) throws KrbException {
        EncryptionKey clientKey = EncryptionHandler.string2Key(userName,
            passPhrase, type);
        return clientKey;
    }

}
