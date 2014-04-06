package org.haox.kerb.server;

import io.netty.channel.socket.SocketChannel;
import net.sf.ehcache.Cache;
import org.apache.directory.api.ldap.model.name.Dn;
import org.haox.kerb.server.common.AbstractKdcServer;
import org.haox.kerb.server.shared.replay.ReplayCache;
import org.haox.kerb.server.shared.replay.ReplayCacheImpl;
import org.haox.kerb.server.shared.store.DirectoryPrincipalStore;
import org.haox.kerb.server.shared.store.PrincipalStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KdcServer extends AbstractKdcServer {
    private static final Logger logger = LoggerFactory.getLogger(KdcServer.class);

    private ReplayCache replayCache;

    public KdcServer() {
        super();
    }

    @Override
    protected String getServiceName() {
        return kdcConfig.getKdcServiceName();
    }

    @Override
    protected void doStart() throws Exception {
        PrincipalStore store = new DirectoryPrincipalStore( getDirectoryService(), new Dn( this.getSearchBaseDn() ) );
        Cache cache = getDirectoryService().getCacheService().getCache( "kdcReplayCache" );
        replayCache = new ReplayCacheImpl( cache, kdcConfig.getAllowableClockSkew());

        startTransport();
    }

    @Override
    protected void doStop() throws Exception {
        stopTransport();

        if ( replayCache != null ) {
            replayCache.clear();
        }
    }

    @Override
    protected void initTransportChannel(SocketChannel ch) {
        ch.pipeline().addLast(new KdcServerHandler());
    }

    public static void main(String[] args) throws Exception {
        int port;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        } else {
            port = 8080;
        }
        new KdcServer().start();
    }
}