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
package org.apache.kerby.config;

import java.util.ArrayList;
import java.util.List;

public class ConfigObject {
    protected static enum VALUE_TYPE { PROPERTY, LIST, CONFIG };

    private VALUE_TYPE valueType;
    private Object value;

    public ConfigObject(String value) {
        this.value = value;
        this.valueType = VALUE_TYPE.PROPERTY;
    }

    public ConfigObject(String[] values) {
        List<String> valuesList = new ArrayList<String>();
        for (String v : values) {
            valuesList.add(v);
        }

        this.value = valuesList;
        this.valueType = VALUE_TYPE.LIST;
    }

    public ConfigObject(List<String> values) {
        if (values != null) {
            this.value = new ArrayList<String>(values);
        } else {
            this.value = new ArrayList<String>();
        }
        this.valueType = VALUE_TYPE.LIST;
    }

    public ConfigObject(Config value) {
        this.value = value;
        this.valueType = VALUE_TYPE.CONFIG;
    }

    public String getPropertyValue() {
        String result = null;
        if (valueType == VALUE_TYPE.PROPERTY) {
            result = (String) value;
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public List<String> getListValues() {
        List<String> results = null;
        if (valueType == VALUE_TYPE.LIST && value instanceof List<?>) {
            results = (List<String>) value;
        }

        return results;
    }

    public Config getConfigValue() {
        Config result = null;
        if (valueType == VALUE_TYPE.CONFIG) {
            result = (Config) value;
        }
        return result;
    }
}
