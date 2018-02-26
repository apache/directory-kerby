/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kerby.has.client;

import org.apache.kerby.has.common.HasException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class HasClientPluginRegistry {
    static final Logger LOG = LoggerFactory.getLogger(HasClientPluginRegistry.class);

    private static Map<String, Class> allPlugins = new ConcurrentHashMap<>();

    static {
        ServiceLoader<HasClientPlugin> plugins = ServiceLoader.load(HasClientPlugin.class);

        for (HasClientPlugin plugin : plugins) {
            allPlugins.put(plugin.getLoginType(), plugin.getClass());
        }
    }

    public static Set<String> registeredPlugins() {
        return Collections.unmodifiableSet(allPlugins.keySet());
    }

    public static boolean registeredPlugin(String name) {
        return allPlugins.containsKey(name);
    }

    public static HasClientPlugin createPlugin(String name) throws HasException {
        if (!registeredPlugin(name)) {
            throw new HasException("Unregistered plugin " + name);
        }
        try {
            return (HasClientPlugin) allPlugins.get(name).newInstance();
        } catch (Exception e) {
            LOG.error("Create {} plugin failed", name, e);
            throw new HasException(e.getMessage());
        }
    }
}
