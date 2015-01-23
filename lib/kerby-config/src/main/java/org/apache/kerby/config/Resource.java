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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.util.Map;
import java.util.Properties;

public class Resource {
    public static enum Format {
        XML_FILE(XmlConfigLoader.class),
        INI_FILE(IniConfigLoader.class),
        JSON_FILE(JsonConfigLoader.class),
        PROPERTIES_FILE(PropertiesFileConfigLoader.class),
        MAP(MapConfigLoader.class),
        PROPERTIES(PropertiesConfigLoader.class);

        private Class<? extends ConfigLoader> loaderClass;

        private Format(Class<? extends ConfigLoader> loaderClass) {
            this.loaderClass = loaderClass;
        }

        public Class<? extends ConfigLoader> getLoaderClass() {
            return loaderClass;
        }
    }

    private String name;
    private Object resource;
    private Format format;

    public static Resource createXmlResource(File xmlFile) throws IOException {
        return new Resource(xmlFile.getName(), xmlFile, Format.XML_FILE);
    }

    public static Resource createIniResource(File iniFile) throws IOException {
        return new Resource(iniFile.getName(), iniFile, Format.INI_FILE);
    }

    public static Resource createJsonResource(File jsonFile) throws IOException {
        return new Resource(jsonFile.getName(), jsonFile, Format.JSON_FILE);
    }

    public static Resource createXmlResource(URL xmlUrl) throws IOException {
        return new Resource(xmlUrl, Format.XML_FILE);
    }

    public static Resource createIniResource(URL iniUrl) throws IOException {
        return new Resource(iniUrl, Format.INI_FILE);
    }

    public static Resource createJsonResource(URL jsonUrl) throws IOException {
        return new Resource(jsonUrl, Format.JSON_FILE);
    }

    public static Resource createMapResource(Map<String,String> mapConfig) {
        return new Resource("mapConfig", mapConfig, Format.MAP);
    }

    public static Resource createPropertiesFileResource(File propFile) throws IOException {
        return new Resource(propFile.getName(), propFile, Format.PROPERTIES_FILE);
    }

    public static Resource createPropertiesResource(Properties propertiesConfig) {
        return new Resource("propConfig", propertiesConfig, Format.PROPERTIES);
    }

    private Resource(String name, File resourceFile, Format format) throws FileNotFoundException {
        this(name, new FileInputStream(resourceFile), format);
    }

    private Resource(URL resourceUrl, Format format) throws IOException {
        this(resourceUrl.toString(), resourceUrl.openStream(), format);
    }

    private Resource(String name, Object resourceStream, Format format) {
        this.name = name;
        this.resource = resourceStream;
        this.format = format;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public Object getResource() {
        return resource;
    }

    public Format getFormat() {
        return format;
    }
}