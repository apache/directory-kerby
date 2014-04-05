package org.haox.config;

public abstract class ConfigLoader {
    private Resource resource;
    private Config config;

    public void setResource(Resource resource) {
        this.resource = resource;
    }

    public Config getConfig() {
        if (config == null) {
            config = new ConfigImpl(resource.getName());
            try {
                loadConfig(config, resource);
            } catch (Exception e) {
                throw new RuntimeException("Failed to load org.haox.config", e);
            }
        }
        return config;
    }

    protected abstract void loadConfig(Config config, Resource resource) throws Exception;
}
