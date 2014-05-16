package org.haox.kerb.server.store;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.shared.kerberos.exceptions.KerberosException;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.SamType;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.util.HashMap;
import java.util.Map;

public class PrincipalStoreEntryModifier
{
    // principal
    private String distinguishedName;
    private String commonName;
    private KerberosPrincipal principal;
    private String realmName;

    // uidObject
    private String userId;

    // KDCEntry
    // must
    private int keyVersionNumber;
    // may
    private KerberosTime validStart;
    private KerberosTime validEnd;
    private KerberosTime passwordEnd;
    private int maxLife;
    private int maxRenew;
    private int kdcFlags;
    private SamType samType;

    private boolean disabled = false;
    private boolean lockedOut = false;
    private KerberosTime expiration = KerberosTime.NEVER;

    private Map<EncryptionType, EncryptionKey> keyMap;


    /**
     * Returns the {@link org.apache.directory.server.kerberos.shared.store.PrincipalStoreEntry}.
     *
     * @return The {@link org.apache.directory.server.kerberos.shared.store.PrincipalStoreEntry}.
     */
    public PrincipalStoreEntry getEntry()
    {
        return new PrincipalStoreEntry( distinguishedName, commonName, userId, principal, keyVersionNumber, validStart,
            validEnd, passwordEnd, maxLife, maxRenew, kdcFlags, keyMap, realmName, samType, disabled, lockedOut,
            expiration );
    }


    /**
     * Sets whether the account is disabled.
     *
     * @param disabled
     */
    public void setDisabled( boolean disabled )
    {
        this.disabled = disabled;
    }


    /**
     * Sets whether the account is locked-out.
     *
     * @param lockedOut
     */
    public void setLockedOut( boolean lockedOut )
    {
        this.lockedOut = lockedOut;
    }


    /**
     * Sets the expiration time.
     *
     * @param expiration
     */
    public void setExpiration( KerberosTime expiration )
    {
        this.expiration = expiration;
    }


    /**
     * Sets the distinguished name (Dn).
     *
     * @param distinguishedName
     */
    public void setDistinguishedName( String distinguishedName )
    {
        this.distinguishedName = distinguishedName;
    }


    /**
     * Sets the common name (cn).
     *
     * @param commonName
     */
    public void setCommonName( String commonName )
    {
        this.commonName = commonName;
    }


    /**
     * Sets the user ID.
     *
     * @param userId
     */
    public void setUserId( String userId )
    {
        this.userId = userId;
    }


    /**
     * Sets the KDC flags.
     *
     * @param kdcFlags
     */
    public void setKDCFlags( int kdcFlags )
    {
        this.kdcFlags = kdcFlags;
    }


    /**
     * Sets the key map.
     *
     * @param keyMap
     */
    public void setKeyMap( Map<EncryptionType, EncryptionKey> keyMap )
    {
        this.keyMap = keyMap;
    }


    /**
     * Sets the key version number.
     *
     * @param keyVersionNumber
     */
    public void setKeyVersionNumber( int keyVersionNumber )
    {
        this.keyVersionNumber = keyVersionNumber;
    }


    /**
     * Sets the ticket maximum life time.
     *
     * @param maxLife
     */
    public void setMaxLife( int maxLife )
    {
        this.maxLife = maxLife;
    }


    /**
     * Sets the ticket maximum renew time.
     *
     * @param maxRenew
     */
    public void setMaxRenew( int maxRenew )
    {
        this.maxRenew = maxRenew;
    }


    /**
     * Sets the end-of-life for the password.
     *
     * @param passwordEnd
     */
    public void setPasswordEnd( KerberosTime passwordEnd )
    {
        this.passwordEnd = passwordEnd;
    }


    /**
     * Sets the principal.
     *
     * @param principal
     */
    public void setPrincipal( KerberosPrincipal principal )
    {
        this.principal = principal;
    }


    /**
     * Sets the realm.
     *
     * @param realmName
     */
    public void setRealmName( String realmName )
    {
        this.realmName = realmName;
    }


    /**
     * Sets the end of validity.
     *
     * @param validEnd
     */
    public void setValidEnd( KerberosTime validEnd )
    {
        this.validEnd = validEnd;
    }


    /**
     * Sets the start of validity.
     *
     * @param validStart
     */
    public void setValidStart( KerberosTime validStart )
    {
        this.validStart = validStart;
    }


    /**
     * Sets the single-use authentication (SAM) type.
     *
     * @param samType
     */
    public void setSamType( SamType samType )
    {
        this.samType = samType;
    }


    /**
     * Converts the ASN.1 encoded key set to a map of encryption types to encryption keys.
     *
     * @param krb5key
     * @return The map of encryption types to encryption keys.
     * @throws LdapException
     * @throws java.io.IOException
     */
    public Map<EncryptionType, EncryptionKey> reconstituteKeyMap( Attribute krb5key ) throws KerberosException, LdapException, KrbException {
        Map<EncryptionType, EncryptionKey> map = new HashMap<EncryptionType, EncryptionKey>();

        for ( Value<?> val : krb5key )
        {
            if ( val instanceof StringValue )
            {
                throw new IllegalStateException( I18n.err( I18n.ERR_626 ) );
            }

            byte[] encryptionKeyBytes = val.getBytes();
            EncryptionKey encryptionKey = KrbCodec.decode(encryptionKeyBytes, EncryptionKey.class);
            map.put( encryptionKey.getKeyType(), encryptionKey );
        }

        return map;
    }
}
