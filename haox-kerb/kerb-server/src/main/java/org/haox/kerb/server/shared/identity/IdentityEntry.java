package org.haox.kerb.server.shared.identity;

import org.apache.directory.shared.kerberos.KerberosTime;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.codec.types.SamType;
import org.apache.directory.shared.kerberos.components.EncryptionKey;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.util.Map;

public class IdentityEntry
{
    // principal
    private String dnName;
    private String cnName;
    private KerberosPrincipal principal;
    private String realm;

    // uidObject
    private String userId;

    // KDCEntry
    private KerberosTime validStart;
    private KerberosTime validEnd;
    private KerberosTime passwordEnd;
    private int keyVersionNumber;
    private int maxLife;
    private int maxRenew;
    private int kdcFlags;
    private SamType samType;

    private boolean disabled;
    private boolean lockedOut;
    private KerberosTime expiration;

    private Map<EncryptionType, EncryptionKey> keyMap;

    public IdentityEntry() {

    }


    /**
     * Returns whether this account is disabled.
     *
     * @return Whether this account is disabled.
     */
    public boolean isDisabled()
    {
        return disabled;
    }


    /**
     * Returns whether this account is locked-out.
     *
     * @return Whether this account is locked-out.
     */
    public boolean isLockedOut()
    {
        return lockedOut;
    }


    /**
     * Returns the expiration time.
     *
     * @return The expiration time.
     */
    public KerberosTime getExpiration()
    {
        return expiration;
    }


    /**
     * Returns the distinguished name.
     *
     * @return The distinguished name.
     */
    public String getDnName()
    {
        return dnName;
    }


    /**
     * Returns the common name.
     *
     * @return The common name.
     */
    public String getCnName()
    {
        return cnName;
    }


    /**
     * Returns the user ID.
     *
     * @return The user ID.
     */
    public String getUserId()
    {
        return userId;
    }


    /**
     * Returns the key map.
     *
     * @return The key map.
     */
    public Map<EncryptionType, EncryptionKey> getKeyMap()
    {
        return keyMap;
    }


    /**
     * Returns the KDC flags.
     *
     * @return The KDC flags.
     */
    public int getKDCFlags()
    {
        return kdcFlags;
    }


    /**
     * Returns the key version number (kvno).
     *
     * @return The key version number (kvno).
     */
    public int getKeyVersionNumber()
    {
        return keyVersionNumber;
    }


    /**
     * Returns the max life.
     *
     * @return The max life.
     */
    public int getMaxLife()
    {
        return maxLife;
    }


    /**
     * Returns the maximum renew time.
     *
     * @return The maximum renew time.
     */
    public int getMaxRenew()
    {
        return maxRenew;
    }


    /**
     * Returns the expiration time for the password.
     *
     * @return The expiration time for the password.
     */
    public KerberosTime getPasswordEnd()
    {
        return passwordEnd;
    }


    /**
     * Returns the principal.
     *
     * @return The principal.
     */
    public KerberosPrincipal getPrincipal()
    {
        return principal;
    }


    /**
     * Returns the realm name.
     *
     * @return The realm name.
     */
    public String getRealm()
    {
        return realm;
    }


    /**
     * Returns the end of validity.
     *
     * @return The end of validity.
     */
    public KerberosTime getValidEnd()
    {
        return validEnd;
    }


    /**
     * Returns the start of validity.
     *
     * @return The start of validity.
     */
    public KerberosTime getValidStart()
    {
        return validStart;
    }


    /**
     * Returns the single-use authentication (SAM) type.
     *
     * @return The single-use authentication (SAM) type.
     */
    public SamType getSamType()
    {
        return samType;
    }
}
