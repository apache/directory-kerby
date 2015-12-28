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

import java.util.Iterator;
import java.util.Map;

public class MapConfigLoader extends ConfigLoader {
    @Override
    protected void loadConfig(ConfigImpl config, Resource resource) {
        @SuppressWarnings("unchecked")
        Map<String, Object> mapConfig = (Map<String, Object>) resource.getResource();
        Iterator iter = mapConfig.entrySet().iterator();
        if (iter.hasNext()) {
            Map.Entry entry = (Map.Entry) iter.next();
            if (entry.getValue() instanceof String) {
                //insert StringMap
                loadStringMap(config, mapConfig);
            }   else {
                //insert objectMap
                loadObjectMap(config, mapConfig);
            }
        }
    }

    private void loadStringMap(ConfigImpl config, Map<String, Object> stringMap) {
        Iterator iter = stringMap.entrySet().iterator();
        while (iter.hasNext()) {
            Map.Entry entry = (Map.Entry) iter.next();
            config.set((String) entry.getKey(), (String) entry.getValue());
        }
    }

    private void loadObjectMap(ConfigImpl config, Map<String, Object> objectMap) {
        Iterator iter = objectMap.entrySet().iterator();
        while (iter.hasNext()) {
            Map.Entry entry = (Map.Entry) iter.next();
            String key = (String) entry.getKey();
            Object value = entry.getValue();

            if (value instanceof Map) {
                ConfigImpl subConfig = new ConfigImpl(key); //new section
                loadSubmap(subConfig, (Map) value);
                config.add(subConfig);
            }   else {
                throw new RuntimeException("Unable to resolve config:" + key);
            }
        }
    }

    private void loadSubmap(ConfigImpl config, Map<String, Object> map) {
        Iterator iter = map.entrySet().iterator();
        while (iter.hasNext()) {
            Map.Entry entry = (Map.Entry) iter.next();
            String key = (String) entry.getKey();
            Object value = entry.getValue();

            if (value instanceof  String) {
                config.set(key, (String) value);
            }
            if (value instanceof Map) {
                ConfigImpl subConfig = new ConfigImpl(key);
                loadSubmap(subConfig, (Map) value);
                config.add(subConfig);
            }
        }
    }
}
