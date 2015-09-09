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
    String getResource();
    Set<String> getNames();

    String getString(String name);
    String getString(ConfigKey name);
    String getString(String name, String defaultValue);

    /**
     * Set a string value for the specified property
     * @param name The property name
     * @param value The string value
     */
    void setString(String name, String value);

    /**
     * Set a string value for the specified property
     * @param name The config key name
     * @param value The string value
     */
    void setString(ConfigKey name, String value);

    String getTrimmed(String name);
    String getTrimmed(ConfigKey name);
    Boolean getBoolean(String name);
    Boolean getBoolean(ConfigKey name);
    Boolean getBoolean(String name, boolean defaultValue);

    /**
     * Set a boolean value for the specified property
     * @param name The property name
     * @param value The boolean value
     */
    void setBoolean(String name, boolean value);

    /**
     * Set a boolean value for the specified property
     * @param name The config key name
     * @param value The boolean value
     */
    void setBoolean(ConfigKey name, boolean value);

    Integer getInt(String name);
    Integer getInt(ConfigKey name);
    Integer getInt(String name, int defaultValue);

    /**
     * Set an int value for the specified property
     * @param name The property name
     * @param value The string value
     */
    void setInt(String name, int value);

    /**
     * Set an int value for the specified property
     * @param name The config key name
     * @param value The int value
     */
    void setInt(ConfigKey name, int value);


    Long getLong(String name);
    Long getLong(ConfigKey name);
    Long getLong(String name, long defaultValue);

    /**
     * Set a long value for the specified property
     * @param name The property name
     * @param value The long value
     */
    void setLong(String name, long value);

    /**
     * Set a long value for the specified property
     * @param name The config key name
     * @param value The long value
     */
    void setLong(ConfigKey name, long value);

    Float getFloat(String name);
    Float getFloat(ConfigKey name);
    Float getFloat(String name, float defaultValue);

    /**
     * Set a float value for the specified property
     * @param name The property name
     * @param value The float value
     */
    void setFloat(String name, float value);

    /**
     * Set a float value for the specified property
     * @param name The config key name
     * @param value The float value
     */
    void setFloat(ConfigKey name, float value);

    List<String> getList(String name);
    List<String> getList(String name, String[] defaultValue);
    List<String> getList(ConfigKey name);
    Config getConfig(String name);
    Config getConfig(ConfigKey name);

    Class<?> getClass(String name) throws ClassNotFoundException;
    Class<?> getClass(String name, Class<?> defaultValue) throws ClassNotFoundException;
    Class<?> getClass(ConfigKey name) throws ClassNotFoundException;
    <T> T getInstance(String name) throws ClassNotFoundException;
    <T> T getInstance(ConfigKey name) throws ClassNotFoundException;
    <T> T getInstance(String name, Class<T> xface) throws ClassNotFoundException;
}
