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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class IniConfigLoader extends ConfigLoader {
    private static final String COMMENT_SYMBOL = "#";

    private ConfigImpl rootConfig;
    private ConfigImpl currentConfig;

    /**
     *  Load configs form the INI configuration format file.
     */
    @Override
    protected void loadConfig(ConfigImpl config, Resource resource) throws IOException {
        rootConfig = config;
        currentConfig = config;

        InputStream is = (InputStream) resource.getResource();
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));

        String line;
        while ((line = reader.readLine()) != null) {
            parseLine(line);
        }
    }

    private void parseLine(String line) {
        line = line.trim();

        if (line.startsWith(COMMENT_SYMBOL)) {
            return;
        }

        if (line.matches("\\[.*\\]")) {
            String subConfigName = line.replaceFirst("\\[(.*)\\]", "$1");
            ConfigImpl subConfig = new ConfigImpl(subConfigName);
            rootConfig.set(subConfigName, subConfig);
            currentConfig = subConfig;
        } else if (line.matches(".*=.*")) {
            int i = line.indexOf('=');
            String name = line.substring(0, i).trim();
            String value = line.substring(i + 1).trim();
            currentConfig.set(name, value);
        }
    }
}
