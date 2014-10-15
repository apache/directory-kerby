package org.haox.kerb.identity;

import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.common.SamType;

import java.util.Map;

public class KrbIdentity extends Identity {
    private PrincipalName principal;
    private String realmName;
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

    public KrbIdentity(String principal, String password) {
        super(principal);
        addAttribute(KrbAttributes.PRINCIPAL, principal);
        addAttribute(KrbAttributes.PASSWORD, password);
    }

    public String getPassword() {
        return getSimpleAttribute(KrbAttributes.PASSWORD);
    }

    public boolean isDisabled()
    {
        return disabled;
    }

    public boolean isLockedOut()
    {
        return lockedOut;
    }

    public KerberosTime getExpiration()
    {
        return expiration;
    }

    public Map<EncryptionType, EncryptionKey> getKeyMap()
    {
        return keyMap;
    }

    public int getKDCFlags()
    {
        return kdcFlags;
    }

    public int getKeyVersionNumber()
    {
        return keyVersionNumber;
    }


    public int getMaxLife()
    {
        return maxLife;
    }


    public int getMaxRenew()
    {
        return maxRenew;
    }


    public KerberosTime getPasswordEnd()
    {
        return passwordEnd;
    }


    public PrincipalName getPrincipal()
    {
        return principal;
    }


    public String getRealmName()
    {
        return realmName;
    }


    public KerberosTime getValidEnd()
    {
        return validEnd;
    }


    public KerberosTime getValidStart()
    {
        return validStart;
    }

}
