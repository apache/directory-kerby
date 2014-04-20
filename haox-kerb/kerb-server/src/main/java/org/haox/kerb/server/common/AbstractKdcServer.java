package org.haox.kerb.server.common;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.haox.kerb.server.identity.IdentityService;
import org.haox.kerb.server.identity.SimpleIdentityBackend;
import org.haox.kerb.server.shared.replay.ReplayCheckService;
import org.haox.kerb.server.shared.replay.ReplayCheckServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public abstract class AbstractKdcServer
{
    private static final Logger logger = LoggerFactory.getLogger(AbstractKdcServer.class);

    private boolean started;
    private String serviceName;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;

    protected KdcConfig kdcConfig;
    protected IdentityService identityService;
    private ReplayCheckService replayCheckService;
    protected File workDir;

    public AbstractKdcServer() {

    }

    public String getKdcRealm() {
        return kdcConfig.getKdcRealm();
    }

    public String getKdcHost() {
        return kdcConfig.getKdcAddress();
    }

    public short getKdcPort() {
        return (short) kdcConfig.getKdcPort();
    }

    public boolean enableDebug() {
        return kdcConfig.enableDebug();
    }

    protected abstract String getServiceName();

    public void init() {
        initConfig();

        this.serviceName = getServiceName();
        this.workDir = getWorkDir();
        this.bossGroup = new NioEventLoopGroup();
        this.workerGroup = new NioEventLoopGroup();

        initIdentityService();
        initReplayCheckService();
    }

    protected File getWorkDir() {
        String path = kdcConfig.getWorkDir();
        File file = new File(path);
        file.mkdirs();
        return file;
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

    public IdentityService getIdentityService() {
        return identityService;
    }

    protected void initIdentityService() {
        File identityFile = new File(workDir, "simplekdb.dat");
        this.identityService = new SimpleIdentityBackend(identityFile);
    }

    public ReplayCheckService getReplayCheckService() {
        return replayCheckService;
    }

    protected void initReplayCheckService() {
        this.replayCheckService = new ReplayCheckServiceImpl();
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
