package org.haox.kerb.server;

import org.apache.directory.shared.kerberos.messages.KerberosMessage;
import org.haox.kerb.server.shared.crypto.encryption.CipherTextHandler;
import org.haox.kerb.server.shared.identity.IdentityService;
import org.haox.kerb.server.shared.replay.ReplayCache;
import org.haox.kerb.server.shared.store.PrincipalStore;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.kdc.KdcReq;

import java.net.InetAddress;


/**
 * The context used to identity the collected and computed data while processing a
 * kerberos message.
 */
public abstract class KdcContext
{
    /** The KDC server configuration */
    private KerberosConfig config;
    private PrincipalStore store;

    /** The request being processed */
    private KdcReq request;

    /** The kerberos response */
    private KerberosMessage reply;

    /** The client IP address */
    private InetAddress clientAddress;
    private CipherTextHandler cipherTextHandler;

    /** The encryption type */
    private EncryptionType encryptionType;

    /** the replay cache */
    private ReplayCache replayCache;

    /**
     * @return Returns the config.
     */
    public KerberosConfig getConfig()
    {
        return config;
    }


    /**
     * @param config The config to set.
     */
    public void setConfig( KerberosConfig config )
    {
        this.config = config;
    }


    /**
     * @return Returns the identity.
     */
    public PrincipalStore getStore()
    {
        return store;
    }


    /**
     * @param store The identity to set.
     */
    public void setStore(PrincipalStore store)
    {
        this.store = store;
    }


    /**
     * @return Returns the request.
     */
    public KdcReq getRequest()
    {
        return request;
    }


    /**
     * @param request The request to set.
     */
    public void setRequest( KdcReq request )
    {
        this.request = request;
    }


    /**
     * @return Returns the reply.
     */
    public KerberosMessage getReply()
    {
        return reply;
    }


    /**
     * @param reply The reply to set.
     */
    public void setReply( KerberosMessage reply )
    {
        this.reply = reply;
    }


    /**
     * @return Returns the clientAddress.
     */
    public InetAddress getClientAddress()
    {
        return clientAddress;
    }


    /**
     * @param clientAddress The clientAddress to set.
     */
    public void setClientAddress( InetAddress clientAddress )
    {
        this.clientAddress = clientAddress;
    }


    /**
     * @return Returns the {@link CipherTextHandler}.
     */
    public CipherTextHandler getCipherTextHandler()
    {
        return cipherTextHandler;
    }


    /**
     * @param cipherTextHandler The {@link CipherTextHandler} to set.
     */
    public void setCipherTextHandler( CipherTextHandler cipherTextHandler )
    {
        this.cipherTextHandler = cipherTextHandler;
    }


    /**
     * Returns the encryption type to use for this session.
     *
     * @return The encryption type.
     */
    public EncryptionType getEncryptionType()
    {
        return encryptionType;
    }


    /**
     * Sets the encryption type to use for this session.
     *
     * @param encryptionType The encryption type to set.
     */
    public void setEncryptionType( EncryptionType encryptionType )
    {
        this.encryptionType = encryptionType;
    }
    
    /**
     * sets the replay cache
     *
     * @param replayCache
     */
    public void setReplayCache( ReplayCache replayCache )
    {
        this.replayCache = replayCache;
    }


    /**
     * @return the replay cache
     */
    public ReplayCache getReplayCache()
    {
        return replayCache;
    }
}
