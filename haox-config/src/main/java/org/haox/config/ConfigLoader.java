package org.haox.config;

public abstract class ConfigLoader {
    private Resource resource;
    private ConfigImpl config;

    protected void setResource(Resource resource) {
        this.resource = resource;
    }

    protected void setConfig(ConfigImpl config) {
        this.config = config;
    }

    public Config load() {
        if (config == null) {
            config = new ConfigImpl(resource.getName());
        }
        config.reset();

        try {
            loadConfig(config, resource);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load org.haox.config", e);
        }

        return this.config;
    }

    protected abstract void loadConfig(ConfigImpl config, Resource resource) throws Exception;
}
