package org.haox.kerb.server;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import net.sf.ehcache.Cache;
import org.apache.directory.api.ldap.model.name.Dn;
import org.haox.kerb.server.shared.replay.ReplayCache;
import org.haox.kerb.server.shared.replay.ReplayCacheImpl;
import org.haox.kerb.server.shared.store.DirectoryPrincipalStore;
import org.haox.kerb.server.shared.store.PrincipalStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KdcServer extends AbstractKdcService {
    private static final Logger LOG = LoggerFactory.getLogger(KdcServer.class);

    /** The default kdc service name */
    private static final String SERVICE_NAME = "Keydap Kerberos Service";

    /** the cache used for storing AS and TGS requests */
    private ReplayCache replayCache;

    private KerberosConfig config;

    private ChangePasswordServer changePwdServer;

    private int port;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;

    /**
     * Creates a new instance of KdcServer with the default configuration.
     */
    public KdcServer()
    {
        this( new KerberosConfig() );
    }


    /**
     *
     * Creates a new instance of KdcServer with the given org.haox.config.
     *
     * @param config the kerberos server configuration
     */
    public KdcServer( KerberosConfig config )
    {
        this.config = config;
        super.setServiceName( SERVICE_NAME );
        super.setSearchBaseDn( config.getSearchBaseDn() );
    }

    public KdcServer(int port) {
        this.port = port;
        bossGroup = new NioEventLoopGroup();
        workerGroup = new NioEventLoopGroup();
    }

    private void startTransport() throws Exception {
        ServerBootstrap b = new ServerBootstrap(); // (2)
        b.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class) // (3)
                .childHandler(new ChannelInitializer<SocketChannel>() { // (4)
                    @Override
                    public void initChannel(SocketChannel ch) throws Exception {
                        ch.pipeline().addLast(new KdcServerHandler());
                    }
                })
                .option(ChannelOption.SO_BACKLOG, 128)          // (5)
                .childOption(ChannelOption.SO_KEEPALIVE, true); // (6)

        b.bind(port);
    }

    public void stopTransport() {
        workerGroup.shutdownGracefully();
        bossGroup.shutdownGracefully();
    }

    public static void main(String[] args) throws Exception {
        int port;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        } else {
            port = 8080;
        }
        new KdcServer(port).start();
    }

    /**
     * @return the replayCache
     */
    public ReplayCache getReplayCache()
    {
        return replayCache;
    }


    /**
     * @throws java.io.IOException if we cannot bind to the sockets
     */
    public void start() throws Exception {
        PrincipalStore store;

        store = new DirectoryPrincipalStore( getDirectoryService(), new Dn( this.getSearchBaseDn() ) );

        LOG.debug( "initializing the kerberos replay cache" );

        Cache cache = getDirectoryService().getCacheService().getCache( "kdcReplayCache" );
        replayCache = new ReplayCacheImpl( cache, config.getAllowableClockSkew() );

        startTransport();

        LOG.info( "Kerberos service started." );

        if ( changePwdServer != null ) {
            changePwdServer.setSearchBaseDn( this.getSearchBaseDn() );
            changePwdServer.start();
        }
    }

    public void stop() {
        stopTransport();

        if ( replayCache != null ) {
            replayCache.clear();
        }

        LOG.info( "Kerberos service stopped." );

        if ( changePwdServer != null ) {
            changePwdServer.stop();
        }
    }

    /**
     * @return the KDC server configuration
     */
    public KerberosConfig getConfig()
    {
        return config;
    }


    public ChangePasswordServer getChangePwdServer()
    {
        return changePwdServer;
    }


    public void setChangePwdServer( ChangePasswordServer changePwdServer )
    {
        this.changePwdServer = changePwdServer;
    }

}