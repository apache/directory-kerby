package org.haox.kerb.server;

import org.haox.kerb.common.KrbUtil;
import org.haox.kerb.crypto.encryption.CipherTextHandler;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.haox.kerb.server.store.PrincipalStore;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.kdc.KdcReq;

import java.net.InetAddress;
import java.util.List;

/**
 * The context used to identity the collected and computed data while processing a
 * kerberos message.
 */
public abstract class KdcContext
{
    /** The KDC server configuration */
    private KdcConfig config;
    private PrincipalStore store;
    private List<EncryptionType> defaultEtypes;

    /** The request being processed */
    private KdcReq request;

    /** The kerberos response */
    private KrbMessage reply;

    /** The client IP address */
    private InetAddress clientAddress;
    private CipherTextHandler cipherTextHandler;

    /** The encryption type */
    private EncryptionType encryptionType;

    /** the replay cache */
    private ReplayCheckService replayCache;

    public KdcConfig getConfig() {
        return config;
    }

    public void setConfig( KdcConfig config ) {
        this.config = config;
    }

    public List<EncryptionType> getDefaultEtypes() {
        if (defaultEtypes == null || defaultEtypes.isEmpty()) {
            defaultEtypes = KrbUtil.getEncryptionTypes(config.getEncryptionTypes());
        }
        return defaultEtypes;
    }

    /**
     * @return Returns the identity.
     */
    public PrincipalStore getStore()
    {
        return store;
    }

    public void setStore(PrincipalStore store)
    {
        this.store = store;
    }

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
    public KrbMessage getReply()
    {
        return reply;
    }


    /**
     * @param reply The reply to set.
     */
    public void setReply(KrbMessage reply )
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
    public void setReplayCache( ReplayCheckService replayCache )
    {
        this.replayCache = replayCache;
    }


    /**
     * @return the replay cache
     */
    public ReplayCheckService getReplayCache()
    {
        return replayCache;
    }
}
