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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public class Conf implements Config {
    private static final Logger LOGGER = LoggerFactory.getLogger(Conf.class);

    private List<ConfigLoader> resourceConfigs;
    private final ConfigImpl config;
    private final Map<String, String> setValues;
    private boolean needReload;

    public Conf() {
        this.resourceConfigs = new ArrayList<ConfigLoader>(1);
        this.config = new ConfigImpl("Conf");
        this.setValues = new HashMap<>(10);
        this.needReload = true;

        addMapConfig(setValues);
    }

    public void addXmlConfig(File xmlFile) throws IOException {
        addResource(Resource.createXmlResource(xmlFile));
    }

    public void addIniConfig(File iniFile) throws IOException {
        addResource(Resource.createIniResource(iniFile));
    }

    public void addJsonConfig(File jsonFile) throws IOException {
        addResource(Resource.createJsonResource(jsonFile));
    }

    public void addPropertiesConfig(File propertiesFile) throws IOException {
        addResource(Resource.createPropertiesFileResource(propertiesFile));
    }

    public void addPropertiesConfig(Properties propertiesConfig) {
        addResource(Resource.createPropertiesResource(propertiesConfig));
    }

    public void addMapConfig(Map<String, String> mapConfig) {
        addResource(Resource.createMapResource(mapConfig));
    }

    public void addResource(Resource resource) {
        ConfigLoader loader = getLoader(resource);
        resourceConfigs.add(loader);
        needReload = true;
    }

    private static ConfigLoader getLoader(Resource resource) {
        ConfigLoader loader = null;

        Class<? extends ConfigLoader> loaderClass = resource.getFormat().getLoaderClass();
        try {
            loader = loaderClass.newInstance();
        } catch (Exception e) {
            LOGGER.error("Failed to create " + Conf.class.getPackage().getName()
                    + " for " + loaderClass.getName(), e);
            throw new RuntimeException("Failed to create "
                    + Conf.class.getPackage().getName() + " for " + loaderClass.getName(), e);
        }
        loader.setResource(resource);
        return loader;
    }

    private void checkAndLoad() {
        if (needReload) {
            reload();
            needReload = false;
        }
    }

    public void reload() {
        config.reset();

        for (ConfigLoader loader : resourceConfigs) {
            Config loaded = loader.load();
            config.add(loaded);
        }
    }

    @Override
    public String getResource() {
        checkAndLoad();
        return config.getResource();
    }

    @Override
    public Set<String> getNames() {
        checkAndLoad();
        return config.getNames();
    }

    @Override
    public String getString(String name) {
        checkAndLoad();
        return config.getString(name);
    }

    @Override
    public String getString(ConfigKey name, boolean useDefault) {
        checkAndLoad();
        return config.getString(name, useDefault);
    }

    @Override
    public String getString(String name, String defaultValue) {
        checkAndLoad();
        return config.getString(name, defaultValue);
    }

    @Override
    public void setString(String name, String value) {
        setValues.put(name, value);
    }

    @Override
    public void setString(ConfigKey name, String value) {
        setString(name.getPropertyKey(), value);
    }

    @Override
    public String getTrimmed(String name) {
        checkAndLoad();
        return config.getTrimmed(name);
    }

    @Override
    public String getTrimmed(ConfigKey name) {
        checkAndLoad();
        return config.getTrimmed(name);
    }

    @Override
    public Boolean getBoolean(String name) {
        checkAndLoad();
        return config.getBoolean(name);
    }

    @Override
    public Boolean getBoolean(ConfigKey name, boolean useDefault) {
        checkAndLoad();
        return config.getBoolean(name, useDefault);
    }

    @Override
    public Boolean getBoolean(String name, Boolean defaultValue) {
        checkAndLoad();
        return config.getBoolean(name, defaultValue);
    }

    @Override
    public void setBoolean(String name, Boolean value) {
        setString(name, String.valueOf(value));
    }

    @Override
    public void setBoolean(ConfigKey name, Boolean value) {
        setString(name.getPropertyKey(), String.valueOf(value));
    }

    @Override
    public Integer getInt(String name) {
        checkAndLoad();
        return config.getInt(name);
    }

    @Override
    public Integer getInt(ConfigKey name, boolean useDefault) {
        checkAndLoad();
        return config.getInt(name, useDefault);
    }

    @Override
    public Integer getInt(String name, Integer defaultValue) {
        checkAndLoad();
        return config.getInt(name, defaultValue);
    }

    @Override
    public void setInt(String name, Integer value) {
        setString(name, String.valueOf(value));
    }

    @Override
    public void setInt(ConfigKey name, Integer value) {
        setString(name.getPropertyKey(), String.valueOf(value));
    }

    @Override
    public Long getLong(String name) {
        checkAndLoad();
        return config.getLong(name);
    }

    @Override
    public Long getLong(ConfigKey name, boolean useDefault) {
        checkAndLoad();
        return config.getLong(name, useDefault);
    }

    @Override
    public Long getLong(String name, Long defaultValue) {
        checkAndLoad();
        return config.getLong(name, defaultValue);
    }

    @Override
    public void setLong(String name, Long value) {
        setString(name, String.valueOf(value));
    }

    @Override
    public void setLong(ConfigKey name, Long value) {
        setString(name.getPropertyKey(), String.valueOf(value));
    }

    @Override
    public Float getFloat(String name) {
        checkAndLoad();
        return config.getFloat(name);
    }

    @Override
    public Float getFloat(ConfigKey name, boolean useDefault) {
        checkAndLoad();
        return config.getFloat(name, useDefault);
    }

    @Override
    public Float getFloat(String name, Float defaultValue) {
        checkAndLoad();
        return config.getFloat(name, defaultValue);
    }

    @Override
    public void setFloat(String name, Float value) {
        setString(name, String.valueOf(value));
    }

    @Override
    public void setFloat(ConfigKey name, Float value) {
        setString(name.getPropertyKey(), String.valueOf(value));
    }

    @Override
    public List<String> getList(String name) {
        checkAndLoad();
        return config.getList(name);
    }

    @Override
    public List<String> getList(String name, String[] defaultValue) {
        checkAndLoad();
        return config.getList(name, defaultValue);
    }

    @Override
    public List<String> getList(ConfigKey name) {
        checkAndLoad();
        return config.getList(name);
    }

    @Override
    public Config getConfig(String name) {
        checkAndLoad();
        return config.getConfig(name);
    }

    @Override
    public Config getConfig(ConfigKey name) {
        checkAndLoad();
        return config.getConfig(name);
    }

    @Override
    public Class<?> getClass(String name) throws ClassNotFoundException {
        checkAndLoad();
        return config.getClass(name);
    }

    @Override
    public Class<?> getClass(String name, Class<?> defaultValue)
            throws ClassNotFoundException {
        checkAndLoad();
        return config.getClass(name, defaultValue);
    }

    @Override
    public Class<?> getClass(ConfigKey name, boolean useDefault)
            throws ClassNotFoundException {
        checkAndLoad();
        return config.getClass(name, useDefault);
    }

    @Override
    public <T> T getInstance(String name) throws ClassNotFoundException {
        checkAndLoad();
        return config.getInstance(name);
    }

    @Override
    public <T> T getInstance(ConfigKey name) throws ClassNotFoundException {
        checkAndLoad();
        return config.getInstance(name);
    }

    @Override
    public <T> T getInstance(String name, Class<T> xface) throws ClassNotFoundException {
        checkAndLoad();
        return config.getInstance(name, xface);
    }
}