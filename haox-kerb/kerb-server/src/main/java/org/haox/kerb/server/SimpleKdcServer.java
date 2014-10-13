package org.haox.kerb.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleKdcServer extends AbstractKdcServer {
    private static final Logger logger = LoggerFactory.getLogger(SimpleKdcServer.class);

    public SimpleKdcServer() {
        super();
    }

    @Override
    protected void initConfig() {
        kdcConfig = new KdcConfig();
    }
}