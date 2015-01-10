package org.apache.haox.config;

import java.util.Properties;

public class PropertiesConfigLoader extends ConfigLoader {

    @Override
    protected void loadConfig(ConfigImpl config, Resource resource) throws Exception {
        Properties propConfig = (Properties) resource.getResource();
        loadConfig(config, propConfig);
    }

    protected void loadConfig(ConfigImpl config, Properties propConfig) {
        Object value;
        for (Object key : propConfig.keySet()) {
            if (key instanceof String) {
                value = propConfig.getProperty((String) key);
                if (value != null && value instanceof String) {
                    config.set((String) key, (String) value);
                }
            }
        }
    }
}
