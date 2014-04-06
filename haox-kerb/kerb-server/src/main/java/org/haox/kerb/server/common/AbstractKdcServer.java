package org.haox.kerb.server.common;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.apache.directory.server.core.api.DirectoryService;
import org.haox.kerb.server.shared.replay.ReplayCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractKdcServer
{
    private static final Logger logger = LoggerFactory.getLogger(AbstractKdcServer.class);

    private boolean started;
    private String serviceName;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;

    protected KdcConfig kdcConfig;
    protected String searchBaseDn;
    protected DirectoryService directoryService;
    protected ReplayCache replayCache;

    public AbstractKdcServer() {

    }

    protected abstract String getServiceName();

    public void init() {
        initConfig();

        this.serviceName = getServiceName();
        this.bossGroup = new NioEventLoopGroup();
        this.workerGroup = new NioEventLoopGroup();
    }

    protected void initConfig() {
        kdcConfig = new KdcConfig();
    }

    public void start() {
        logger.info("Starting " + serviceName);
        try {
            doStart();
        } catch (Exception e) {
            throw new RuntimeException("Failed to start " + getServiceName());
        }
        logger.info("Started " + serviceName);
    }

    protected abstract void doStart() throws Exception;

    public void stop() {
        logger.info("Stopping " + serviceName);
        try {
            doStop();
        } catch (Exception e) {
            throw new RuntimeException("Failed to stop " + getServiceName());
        }
        logger.info("Stopped " + serviceName);
    }

    protected abstract void doStop() throws Exception;

    public KdcConfig getConfig() {
        return kdcConfig;
    }

    public boolean isStarted() {
        return started;
    }

    protected void setStarted( boolean started ) {
        this.started = started;
    }

    protected void setServiceName( String name ) {
        this.serviceName = name;
    }

    public DirectoryService getDirectoryService() {
        return directoryService;
    }

    protected void setDirectoryService( DirectoryService directoryService ) {
        this.directoryService = directoryService;
    }

    public String getSearchBaseDn() {
        return searchBaseDn;
    }

    protected void setSearchBaseDn( String searchBaseDn ) {
        this.searchBaseDn = searchBaseDn;
    }

    public ReplayCache getReplayCache() {
        return replayCache;
    }

    protected void startTransport() throws Exception {
        ServerBootstrap b = new ServerBootstrap();
        b.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    public void initChannel(SocketChannel ch) throws Exception {
                        initTransportChannel(ch);
                    }
                })
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true);

        b.bind(kdcConfig.getKdcPort());
    }

    protected abstract void initTransportChannel(SocketChannel ch);

    protected void stopTransport() throws Exception {
        workerGroup.shutdownGracefully();
        bossGroup.shutdownGracefully();
    }
}
