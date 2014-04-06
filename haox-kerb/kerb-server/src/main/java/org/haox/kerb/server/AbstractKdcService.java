package org.haox.kerb.server;

import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.api.DirectoryService;

public abstract class AbstractKdcService
{
    /** A flag set to indicate if the server is started or not */
    private boolean started;

    /** A flag set to tell if the server is enabled or not */
    private boolean enabled;

    /** The server ID */
    private String serviceId;

    /** The service name */
    private String serviceName;

    /**
     * The single location where entries are stored.  If this service
     * is catalog based the store will search the system partition
     * configuration for catalog entries.  Otherwise it will use this
     * search base as a single point of searching the DIT.
     */
    private String searchBaseDn = ServerDNConstants.USER_EXAMPLE_COM_DN;

    /** determines if the search base is pointer to a catalog or a single entry point */
    private boolean catelogBased;

    /** directory service core where protocol data is backed */
    private DirectoryService directoryService;

    /**
     * {@inheritDoc}
     */
    public boolean isStarted()
    {
        return started;
    }


    /**
     * @param started The state of this server
     */
    protected void setStarted( boolean started )
    {
        this.started = started;
    }


    /**
     * {@inheritDoc}
     */
    public boolean isEnabled()
    {
        return enabled;
    }


    /**
     * {@inheritDoc}
     */
    public void setEnabled( boolean enabled )
    {
        this.enabled = enabled;
    }


    /**
     * {@inheritDoc}
     */
    public String getServiceId()
    {
        return serviceId;
    }


    /**
     * {@inheritDoc}
     */
    public void setServiceId( String serviceId )
    {
        this.serviceId = serviceId;
    }


    /**
     * {@inheritDoc}
     */
    public String getServiceName()
    {
        return serviceName;
    }


    /**
     * {@inheritDoc}
     */
    public void setServiceName( String name )
    {
        this.serviceName = name;
    }

    public DirectoryService getDirectoryService()
    {
        return directoryService;
    }


    /**
     */
    public void setDirectoryService( DirectoryService directoryService )
    {
        this.directoryService = directoryService;
    }


    /**
     * Returns the search base Dn.
     *
     * @return The search base Dn.
     */
    public String getSearchBaseDn()
    {
        return searchBaseDn;
    }


    /**
     * @param searchBaseDn The searchBaseDn to set.
     */
    public void setSearchBaseDn( String searchBaseDn )
    {
        this.searchBaseDn = searchBaseDn;
    }
}
