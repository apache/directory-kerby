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

import org.apache.kerby.config.Conf;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Help KrbConfig and KdcConfig to load configs.
 */
public class KrbConfHelper {
    /**
     * The regex to split a config value(string) to a list of config value(string list).
     */
    private static final String LIST_SPLITTER = " ";

    public static String getStringUnderSection(Conf conf, SectionConfigKey key) {
        Config subConfig = conf.getConfig(key.getSectionName());
        if (subConfig != null) {
            return subConfig.getString(key);
        } else {
            return (String) key.getDefaultValue();
        }
    }

    public static boolean getBooleanUnderSection(Conf conf, SectionConfigKey key) {
        Config subConfig = conf.getConfig(key.getSectionName());
        if (subConfig != null) {
            return subConfig.getBoolean(key);
        } else {
            return (Boolean) key.getDefaultValue();
        }
    }

    public static long getLongUnderSection(Conf conf, SectionConfigKey key) {
        Config subConfig = conf.getConfig(key.getSectionName());
        if (subConfig != null) {
            return subConfig.getLong(key);
        } else {
            return (Long) key.getDefaultValue();
        }
    }

    public static int getIntUnderSection(Conf conf, SectionConfigKey key) {
        Config subConfig = conf.getConfig(key.getSectionName());
        if (subConfig != null) {
            return subConfig.getInt(key);
        } else {
            return (Integer) key.getDefaultValue();
        }
    }

    public static String[] getStringArrayUnderSection(Conf conf, SectionConfigKey key) {
        String value = getStringUnderSection(conf, key);
        String[] values = value.split(LIST_SPLITTER);
        return values;
    }

    public static List<EncryptionType> getEncTypesUnderSection(Conf conf, SectionConfigKey key) {
        String[] encTypesNames = getStringArrayUnderSection(conf, key);
        return getEncryptionTypes(encTypesNames);
    }

    public static List<EncryptionType> getEncryptionTypes(String[] encTypeNames) {
        return getEncryptionTypes(Arrays.asList(encTypeNames));
    }

    public static List<EncryptionType> getEncryptionTypes(List<String> encTypeNames) {
        List<EncryptionType> results = new ArrayList<EncryptionType>(encTypeNames.size());

        for (String eTypeName : encTypeNames) {
            EncryptionType eType = EncryptionType.fromName(eTypeName);
            if (eType != EncryptionType.NONE) {
                results.add(eType);
            }
        }
        return results;
    }

}
