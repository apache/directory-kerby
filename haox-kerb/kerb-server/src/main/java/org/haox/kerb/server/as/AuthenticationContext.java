package org.haox.kerb.server.as;

import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.shared.store.PrincipalStoreEntry;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.ticket.Ticket;

/**
 * A context used to identity and manage Authentication elements
 */
public class AuthenticationContext extends KdcContext
{
    /** The Kerberos Ticket associated to this context */
    private Ticket ticket;

    /** The client key */
    private EncryptionKey clientKey;

    /** The client entry */
    private PrincipalStoreEntry clientEntry;

    /** The server entry */
    private PrincipalStoreEntry serverEntry;

    /** Tell if we have had a pre-authentication */
    private boolean isPreAuthenticated;


    /**
     * @return Returns the serverEntry.
     */
    public PrincipalStoreEntry getServerEntry()
    {
        return serverEntry;
    }


    /**
     * @param serverEntry The serverEntry to set.
     */
    public void setServerEntry( PrincipalStoreEntry serverEntry )
    {
        this.serverEntry = serverEntry;
    }


    /**
     * @return Returns the clientEntry.
     */
    public PrincipalStoreEntry getClientEntry()
    {
        return clientEntry;
    }


    /**
     * @param clientEntry The clientEntry to set.
     */
    public void setClientEntry( PrincipalStoreEntry clientEntry )
    {
        this.clientEntry = clientEntry;
    }

    /**
     * @return Returns the clientKey.
     */
    public EncryptionKey getClientKey()
    {
        return clientKey;
    }


    /**
     * @param clientKey The clientKey to set.
     */
    public void setClientKey( EncryptionKey clientKey )
    {
        this.clientKey = clientKey;
    }


    /**
     * @return Returns the ticket.
     */
    public Ticket getTicket()
    {
        return ticket;
    }


    /**
     * @param ticket The ticket to set.
     */
    public void setTicket( Ticket ticket )
    {
        this.ticket = ticket;
    }


    /**
     * @return true if the client used pre-authentication.
     */
    public boolean isPreAuthenticated()
    {
        return isPreAuthenticated;
    }

    /**
     * @param isPreAuthenticated Whether the client used pre-authentication.
     */
    public void setPreAuthenticated( boolean isPreAuthenticated )
    {
        this.isPreAuthenticated = isPreAuthenticated;
    }
}
