package org.haox.kerb.server.changepasswd;

import io.netty.channel.socket.SocketChannel;
import org.haox.kerb.server.common.AbstractKdcServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ChangePasswordServer extends AbstractKdcServer
{
    private static final Logger logger = LoggerFactory.getLogger(ChangePasswordServer.class);

    private ChangePasswordConfig changePasswordConfig;

    public ChangePasswordServer() {
        super();
    }

    @Override
    protected void initConfig() {
        super.initConfig();
        this.changePasswordConfig = (ChangePasswordConfig) getConfig();
    }

    @Override
    protected String getServiceName() {
        return changePasswordConfig.getServiceName();
    }

    @Override
    protected void doStart() throws Exception {

    }

    @Override
    protected void doStop() throws Exception {

    }

    @Override
    protected void initTransportChannel(SocketChannel ch) {

    }
}
