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

public interface Config {
    public String getResource();
    public Set<String> getNames();

    public String getString(String name);
    public String getString(ConfigKey name);
    public String getString(String name, String defaultValue);
    public String getTrimmed(String name);
    public String getTrimmed(ConfigKey name);
    public Boolean getBoolean(String name);
    public Boolean getBoolean(ConfigKey name);
    public Boolean getBoolean(String name, boolean defaultValue);
    public Integer getInt(String name);
    public Integer getInt(ConfigKey name);
    public Integer getInt(String name, int defaultValue);
    public Long getLong(String name);
    public Long getLong(ConfigKey name);
    public Long getLong(String name, long defaultValue);
    public Float getFloat(String name);
    public Float getFloat(ConfigKey name);
    public Float getFloat(String name, float defaultValue);
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
