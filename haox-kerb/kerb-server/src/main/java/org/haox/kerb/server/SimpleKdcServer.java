package org.haox.kerb.server;

import io.netty.channel.socket.SocketChannel;
import org.haox.kerb.server.common.AbstractKdcServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleKdcServer extends AbstractKdcServer {
    private static final Logger logger = LoggerFactory.getLogger(SimpleKdcServer.class);

    public SimpleKdcServer() {
        super();
    }

    @Override
    protected String getServiceName() {
        return kdcConfig.getKdcServiceName();
    }

    @Override
    protected void doStart() throws Exception {
        startTransport();
    }

    @Override
    protected void doStop() throws Exception {
        stopTransport();
    }

    private void initKDCServer() throws Exception {

    }

    public static void main(String[] args) throws Exception {
        int port;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        } else {
            port = 8080;
        }
        new SimpleKdcServer().start();
    }
}