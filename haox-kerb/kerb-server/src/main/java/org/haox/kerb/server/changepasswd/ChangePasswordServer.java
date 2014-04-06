package org.haox.kerb.server.changepasswd;

import io.netty.channel.socket.SocketChannel;
import net.sf.ehcache.Cache;
import org.apache.directory.api.ldap.model.name.Dn;
import org.haox.kerb.server.common.AbstractKdcServer;
import org.haox.kerb.server.shared.replay.ReplayCacheImpl;
import org.haox.kerb.server.shared.store.DirectoryPrincipalStore;
import org.haox.kerb.server.shared.store.PrincipalStore;
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
        PrincipalStore store = new DirectoryPrincipalStore( getDirectoryService(), new Dn( this.getSearchBaseDn() ) );
        Cache cache = getDirectoryService().getCacheService().getCache( "changePwdReplayCache" );
        replayCache = new ReplayCacheImpl( cache );
    }

    @Override
    protected void doStop() throws Exception {
        replayCache.clear();
    }

    @Override
    protected void initTransportChannel(SocketChannel ch) {

    }
}
