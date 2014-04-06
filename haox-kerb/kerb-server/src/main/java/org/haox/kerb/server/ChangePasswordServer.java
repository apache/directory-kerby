package org.haox.kerb.server;

import net.sf.ehcache.Cache;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.haox.kerb.server.shared.replay.ReplayCache;
import org.haox.kerb.server.shared.replay.ReplayCacheImpl;
import org.haox.kerb.server.shared.store.DirectoryPrincipalStore;
import org.haox.kerb.server.shared.store.PrincipalStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class ChangePasswordServer extends AbstractKdcService
{
    /** logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( ChangePasswordServer.class );

    /** The default change password port. */
    private static final int DEFAULT_IP_PORT = 464;

    /** The default change password password policy for password length. */
    public static final int DEFAULT_PASSWORD_LENGTH = 6;

    /** The default change password password policy for category count. */
    public static final int DEFAULT_CATEGORY_COUNT = 3;

    /** The default change password password policy for token size. */
    public static final int DEFAULT_TOKEN_SIZE = 3;

    private ChangePasswordConfig config;

    /** the cache used for storing change password requests */
    private ReplayCache replayCache;


    /**
     * Creates a new instance of ChangePasswordConfiguration.
     */
    public ChangePasswordServer()
    {
        this( new ChangePasswordConfig() );
    }


    public ChangePasswordServer(ChangePasswordConfig config)
    {
        this.config = config;
    }


    /**
     * @throws java.io.IOException if we cannot bind to the specified ports
     */
    public void start() throws IOException, LdapInvalidDnException
    {
        PrincipalStore store = new DirectoryPrincipalStore( getDirectoryService(), new Dn( this.getSearchBaseDn() ) );

        LOG.debug( "initializing the changepassword replay cache" );

        Cache cache = getDirectoryService().getCacheService().getCache( "changePwdReplayCache" );
        replayCache = new ReplayCacheImpl( cache );

        /*
        for ( Transport transport : transports )
        {
            IoAcceptor acceptor = transport.getAcceptor();

            // Disable the disconnection of the clients on unbind
            acceptor.setCloseOnDeactivation( false );

            if ( transport instanceof UdpTransport )
            {
                // Allow the port to be reused even if the socket is in TIME_WAIT state
                ( ( DatagramSessionConfig ) acceptor.getSessionConfig() ).setReuseAddress( true );
            }
            else
            {
                // Allow the port to be reused even if the socket is in TIME_WAIT state
                ( ( SocketAcceptor ) acceptor ).setReuseAddress( true );

                // No Nagle's algorithm
                ( ( SocketAcceptor ) acceptor ).getSessionConfig().setTcpNoDelay( true );
            }

            // Set the handler
            acceptor.setHandler( new ChangePasswordProtocolHandler( this, store ) );

            // Bind
            acceptor.bind();
        }
        */
        LOG.info( "ChangePassword service started." );
        //System.out.println( "ChangePassword service started." );
    }


    public void stop() {
        /*
        for ( Transport transport : getTransports() )
        {
            IoAcceptor acceptor = transport.getAcceptor();

            if ( acceptor != null )
            {
                acceptor.dispose();
            }
        } */

        replayCache.clear();

        LOG.info( "ChangePassword service stopped." );
        //System.out.println( "ChangePassword service stopped." );
    }


    /**
     * @return the replayCache
     */
    public ReplayCache getReplayCache()
    {
        return replayCache;
    }


    public ChangePasswordConfig getConfig()
    {
        return config;
    }
}
