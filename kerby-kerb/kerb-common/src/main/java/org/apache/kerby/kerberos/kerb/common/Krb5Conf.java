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
import org.apache.kerby.config.ConfigKey;
import org.apache.kerby.config.Resource;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * A krb5.conf format support.
 */
public class Krb5Conf extends Conf {
    /**
     * The regex to split a config value(string) to a list 
     * of config value(string list).
     */
    private static final String LIST_SPLITTER = " |,";
    private Map<String, Object> krb5Map;

    public void addKrb5Config(File krb5File) throws IOException {
        Krb5Parser krb5Parser = new Krb5Parser(krb5File);
        krb5Parser.load();
        krb5Map = krb5Parser.getItems();
        addResource(Resource.createMapResource(krb5Map));
    }

    protected String getString(ConfigKey key, boolean useDefault,
                            String ... sections) {
        String value = getString(key, false);
        if (value == null) {
            for (String section : sections) {
                Config subConfig = getConfig(section);
                if (subConfig != null) {
                    value = subConfig.getString(key, false);
                    if (value != null) {
                        break;
                    }
                }
            }
        }
        if (value == null && useDefault) {
            value = (String) key.getDefaultValue();
        }

        return value;
    }

    protected Boolean getBoolean(ConfigKey key, boolean useDefault,
                                 String ... sections) {
        Boolean value = getBoolean(key, false);
        if (value == null) {
            for (String section : sections) {
                Config subConfig = getConfig(section);
                if (subConfig != null) {
                    value = subConfig.getBoolean(key, false);
                    if (value != null) {
                        break;
                    }
                }
            }
        }
        if (value == null && useDefault) {
            value = (Boolean) key.getDefaultValue();
        }

        return value;
    }

    protected Long getLong(ConfigKey key, boolean useDefault,
                           String ... sections) {
        Long value = getLong(key, false);
        if (value == null) {
            for (String section : sections) {
                Config subConfig = getConfig(section);
                if (subConfig != null) {
                    value = subConfig.getLong(key, false);
                    if (value != null) {
                        break;
                    }
                }
            }
        }
        if (value == null && useDefault) {
            value = (Long) key.getDefaultValue();
        }

        return value;
    }

    protected Integer getInt(ConfigKey key, boolean useDefault,
                             String ... sections) {
        Integer value = getInt(key, false);
        if (value == null) {
            for (String section : sections) {
                Config subConfig = getConfig(section);
                if (subConfig != null) {
                    value = subConfig.getInt(key, false);
                    if (value != null) {
                        break;
                    }
                }
            }
        }
        if (value == null && useDefault) {
            value = (Integer) key.getDefaultValue();
        }

        return value;
    }

    protected List<EncryptionType> getEncTypes(ConfigKey key, boolean useDefault,
                                               String ... sections) {
        String[] encTypesNames = getStringArray(key, useDefault, sections);
        return getEncryptionTypes(encTypesNames);
    }

    protected List<EncryptionType> getEncryptionTypes(String[] encTypeNames) {
        return getEncryptionTypes(Arrays.asList(encTypeNames));
    }

    protected List<EncryptionType> getEncryptionTypes(List<String> encTypeNames) {
        List<EncryptionType> results = new ArrayList<>(encTypeNames.size());

        for (String eTypeName : encTypeNames) {
            EncryptionType eType = EncryptionType.fromName(eTypeName);
            if (eType != EncryptionType.NONE) {
                results.add(eType);
            }
        }

        return results;
    }

    protected String[] getStringArray(ConfigKey key, boolean useDefault,
                                      String ... sections) {
        String value = getString(key, useDefault, sections);
        String[] values = value.split(LIST_SPLITTER);
        return values;
    }

    protected Object getSection(String sectionName) {
        if (krb5Map != null) {
            for (Map.Entry<String, Object> entry : krb5Map.entrySet()) {
                if (entry.getKey().equals(sectionName)) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }
}
