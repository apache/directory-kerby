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

import java.util.List;
import java.util.Set;

/**
 * Config API to get configuration properties from resources, like XML, Json,
 * ini, Java Properties and Map. It doesn't support writing back. It allows to
 * set configuration properties to ease the preparation of a Config.
 */
public interface Config {
    public String getResource();
    public Set<String> getNames();

    public String getString(String name);
    public String getString(ConfigKey name);
    public String getString(String name, String defaultValue);

    /**
     * Set a string value for the specified property
     * @param name
     * @param value
     */
    public void setString(String name, String value);

    /**
     * Set a string value for the specified property
     * @param name
     * @param value
     */
    public void setString(ConfigKey name, String value);

    public String getTrimmed(String name);
    public String getTrimmed(ConfigKey name);
    public Boolean getBoolean(String name);
    public Boolean getBoolean(ConfigKey name);
    public Boolean getBoolean(String name, boolean defaultValue);

    /**
     * Set a boolean value for the specified property
     * @param name
     * @param value
     */
    public void setBoolean(String name, boolean value);

    /**
     * Set a boolean value for the specified property
     * @param name
     * @param value
     */
    public void setBoolean(ConfigKey name, boolean value);

    public Integer getInt(String name);
    public Integer getInt(ConfigKey name);
    public Integer getInt(String name, int defaultValue);

    /**
     * Set an int value for the specified property
     * @param name
     * @param value
     */
    public void setInt(String name, int value);

    /**
     * Set an int value for the specified property
     * @param name
     * @param value
     */
    public void setInt(ConfigKey name, int value);


    public Long getLong(String name);
    public Long getLong(ConfigKey name);
    public Long getLong(String name, long defaultValue);

    /**
     * Set a long value for the specified property
     * @param name
     * @param value
     */
    public void setLong(String name, long value);

    /**
     * Set a long value for the specified property
     * @param name
     * @param value
     */
    public void setLong(ConfigKey name, long value);

    public Float getFloat(String name);
    public Float getFloat(ConfigKey name);
    public Float getFloat(String name, float defaultValue);

    /**
     * Set a float value for the specified property
     * @param name
     * @param value
     */
    public void setFloat(String name, float value);

    /**
     * Set a float value for the specified property
     * @param name
     * @param value
     */
    public void setFloat(ConfigKey name, float value);

    public List<String> getList(String name);
    public List<String> getList(String name, String[] defaultValue);
    public List<String> getList(ConfigKey name);
    public Config getConfig(String name);
    public Config getConfig(ConfigKey name);

    public Class<?> getClass(String name) throws ClassNotFoundException;
    public Class<?> getClass(String name, Class<?> defaultValue) throws ClassNotFoundException;
    public Class<?> getClass(ConfigKey name) throws ClassNotFoundException;
    public <T> T getInstance(String name) throws ClassNotFoundException;
    public <T> T getInstance(ConfigKey name) throws ClassNotFoundException;
    public <T> T getInstance(String name, Class<T> xface) throws ClassNotFoundException;
}
