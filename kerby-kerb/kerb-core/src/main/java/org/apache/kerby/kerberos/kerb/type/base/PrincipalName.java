/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kerb.type.base;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KerberosStrings;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 * The PrincipalName as defined in RFC 4120 :
 * 
 * <pre>
 * PrincipalName   ::= SEQUENCE {
 *     name-type       [0] Int32,
 *     name-string     [1] SEQUENCE OF KerberosString
 * }
 * </pre>
 * 
 * The possible <tt>name-type</tt> are :
 * <ul>
 *   <li>NT-UNKNOWN        (0)  : Name type not known</li>
 *   <li>NT-PRINCIPAL      (1)  : Just the name of the principal as in DCE, or for users</li>
 *   <li>NT-SRV-INST       (2)  : Service and other unique instance (krbtgt)</li>
 *   <li>NT-SRV-HST        (3)  : Service with host name as instance (telnet, rcommands)</li>
 *   <li>NT-SRV-XHST       (4)  : Service with host as remaining components</li>
 *   <li>NT-UID            (5)  : Unique ID</li>
 *   <li>NT-X500-PRINCIPAL (6)  : Encoded X.509 Distinguished name [RFC2253]</li>
 *   <li>NT-SMTP-NAME      (7)  : Name in form of SMTP email name (e.g., user@example.com)</li>
 *   <li>NT-ENTERPRISE     (10) : Enterprise name - may be mapped to principal name</li>
 *   <li>NT_WELLKNOWN      (11) : Well-known principal names (RFC 6111).
 * </ul>
 * 
 * The <tt>name-string</tt> contains 
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PrincipalName extends KrbSequenceType {
    /**
     * The possible fields
     */
    protected enum PrincipalNameField implements EnumType {
        NAME_TYPE,
        NAME_STRING;

        /**
         * {@inheritDoc}
         */
        @Override
        public int getValue() {
            return ordinal();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getName() {
            return name();
        }
    }

    /** The PrincipalName's fields */
    private static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(PrincipalNameField.NAME_TYPE, Asn1Integer.class),
            new ExplicitField(PrincipalNameField.NAME_STRING, KerberosStrings.class)
    };
    
    /** The PrincipalName's realm */
    private String realm;

    /**
     * Creates a PrincipalName instance
     */
    public PrincipalName() {
        super(fieldInfos);
    }

    /**
     * Creates a PrincipalName instance, using a NT_PRINCIPAL name
     * 
     * @param nameString The PrincipalName as a String
     */
    public PrincipalName(String nameString) {
        super(fieldInfos);
        setNameType(NameType.NT_PRINCIPAL);
        fromNameString(nameString);
    }

    /**
     * Creates a PrincipalName instance, using a given type
     * 
     * @param nameString The PrincipalName as a String
     * @param type The nameType to use
     */
    public PrincipalName(String nameString, NameType type) {
        super(fieldInfos);
        fromNameString(nameString);
        setNameType(type);
    }

    /**
     * Creates a PrincipalName instance, using a given type and 
     * a list of components
     * 
     * @param nameStrings The components to use
     * @param nameType The nameType to use
     */
    public PrincipalName(List<String> nameStrings, NameType nameType) {
        super(fieldInfos);
        setNameStrings(nameStrings);
        setNameType(nameType);
    }

    /**
     * Get the Realm from the name.
     * 
     * @param principal The PrincipalName from which we want to extract the Realm
     * @return The extracted Realm
     */
    public static String extractRealm(String principal) {
        int pos = principal.indexOf('@');

        if (pos > 0) {
            return principal.substring(pos + 1);
        }

        throw new IllegalArgumentException("Not a valid principal, missing realm name");
    }

    /**
     * Get the name part of the PrincipalName, ie, discading the realm part of it.
     * 
     * @param principal The PrincipalName to split
     * @return The extracted components (primary/instances)
     */
    public static String extractName(String principal) {
        int pos = principal.indexOf('@');

        if (pos < 0) {
            return principal;
        }

        return principal.substring(0, pos);
    }

    /**
     * Create a SALT based on the PrincipalName, accordingly to RFC 4120 :
     * "The default salt string, if none is provided via pre-authentication
     * data, is the concatenation of the principal's realm and name components,
     * in order, with no separators."
     * 
     * @param principalName The PrincipalName for which we want to create a salt
     * @return The created salt 
     */
    public static String makeSalt(PrincipalName principalName) {
        StringBuilder salt = new StringBuilder();
        
        if (principalName.getRealm() != null) {
            salt.append(principalName.getRealm());
        }
        
        List<String> nameStrings = principalName.getNameStrings();
        
        for (String ns : nameStrings) {
            salt.append(ns);
        }
        
        return salt.toString();
    }

    /**
     * @return The NameType of this PirncipalName
     */
    public NameType getNameType() {
        Integer value = getFieldAsInteger(PrincipalNameField.NAME_TYPE);
        
        return NameType.fromValue(value);
    }

    /**
     * Set the NameType field of this PrincipalName
     * 
     * @param nameType The NameType to store
     */
    public void setNameType(NameType nameType) {
        setFieldAsInt(PrincipalNameField.NAME_TYPE, nameType.getValue());
    }

    /**
     * @return The PrincipalName's components as a list of String
     */
    public List<String> getNameStrings() {
        KerberosStrings krbStrings = getFieldAs(PrincipalNameField.NAME_STRING, KerberosStrings.class);
        
        if (krbStrings != null) {
            return krbStrings.getAsStrings();
        }
        
        return Collections.emptyList();
    }

    /**
     * Stores the components of a PrincipalName into the associated ASN1 structure
     * @param nameStrings The PrincipalName's components
     */
    public void setNameStrings(List<String> nameStrings) {
        setFieldAs(PrincipalNameField.NAME_STRING, new KerberosStrings(nameStrings));
    }

    /**
     * @return The PrincipalName's Realm
     */
    public String getRealm() {
        return realm;
    }

    /**
     * Store a Realm in this PrincipalName
     * @param realm The Realm to store
     */
    public void setRealm(String realm) {
        this.realm = realm;
    }

    /**
     * @return A String representation of this PrincipalName, as primary [ '/' instance ]* [ '@' realm ]
     */
    public String getName() {
        return makeSingleName();
    }

    /**
     * Reconstruct the PrincipalName String from teh stored components
     */
    private String makeSingleName() {
        List<String> names = getNameStrings();
        StringBuilder sb = new StringBuilder();
        boolean isFirst = true;
        
        for (String name : names) {
            if (isFirst) {
                isFirst = false;
            } else {
                sb.append('/');
            }
            
            sb.append(name);
        }

        if (realm != null && !realm.isEmpty()) {
            sb.append('@');
            sb.append(realm);
        }

        return sb.toString();
    }
    
    /**
     * Splits the given NameString into components (primary, instances and realm) :
     * primary [ / instance]* [ @ realm ]
     * 
     * Note : we will have only one instance, AFAICT...
     */
    private void fromNameString(String nameString) {
        if (nameString == null) {
            return;
        }
        
        List<String> nameStrings;
        int realmPos = nameString.indexOf('@');
        String nameParts;
        
        if (realmPos != -1) {
            nameParts = nameString.substring(0, realmPos);
            realm = nameString.substring(realmPos + 1);
        } else {
            nameParts = nameString;
        }
        
        String[] parts = nameParts.split("\\/");
        nameStrings = Arrays.asList(parts);

        setNameStrings(nameStrings);
    }

    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode() {
        return getName().hashCode();
    }

    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }

        if (!(other instanceof PrincipalName)) {
            return false;
        }
        
        PrincipalName otherPrincipal = (PrincipalName) other;
        
        return getNameType() == ((PrincipalName) other).getNameType() 
                && getName().equals(otherPrincipal.getName());
    }

    /**
     * @see Object#toString()
     */
    @Override
    public String toString() {
        return getName();
    }
}
