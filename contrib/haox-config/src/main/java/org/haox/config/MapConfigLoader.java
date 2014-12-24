package org.haox.config;

import java.util.Map;

public class MapConfigLoader extends ConfigLoader {
    @Override
    protected void loadConfig(ConfigImpl config, Resource resource) {
        Map<String, String> mapConfig = (Map<String, String>) resource.getResource();
        String value;
        for (String key : mapConfig.keySet()) {
            value = mapConfig.get(key);
            config.set(key, value);
        }
    }
}
