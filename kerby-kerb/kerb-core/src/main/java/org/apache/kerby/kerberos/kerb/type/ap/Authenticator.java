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
package org.apache.kerby.kerberos.kerb.type.ap;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.type.KerberosString;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

/**
 * The definition of the unencrypted AUthenticator, per RFC 4120, section 5.5.1 :
 * <pre>
 * Authenticator   ::= [APPLICATION 2] SEQUENCE  {
 *         authenticator-vno       [0] INTEGER (5),
 *         crealm                  [1] Realm,
 *         cname                   [2] PrincipalName,
 *         cksum                   [3] Checksum OPTIONAL,
 *         cusec                   [4] Microseconds,
 *         ctime                   [5] KerberosTime,
 *         subkey                  [6] EncryptionKey OPTIONAL,
 *         seq-number              [7] UInt32 OPTIONAL,
 *         authorization-data      [8] AuthorizationData OPTIONAL
 * }
 * </pre>
 */
public class Authenticator extends KrbAppSequenceType {
    /** The APPLICATION TAG */
    public static final int TAG = 2;

    /**
     * The possible fields
     */
    protected enum AuthenticatorField implements EnumType {
        AUTHENTICATOR_VNO,
        CREALM,
        CNAME,
        CKSUM,
        CUSEC,
        CTIME,
        SUBKEY,
        SEQ_NUMBER,
        AUTHORIZATION_DATA;

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

    /** The ApReq's fields */
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(AuthenticatorField.AUTHENTICATOR_VNO, Asn1Integer.class),
            new ExplicitField(AuthenticatorField.CREALM, KerberosString.class),
            new ExplicitField(AuthenticatorField.CNAME, PrincipalName.class),
            new ExplicitField(AuthenticatorField.CKSUM, CheckSum.class),
            new ExplicitField(AuthenticatorField.CUSEC, Asn1Integer.class),
            new ExplicitField(AuthenticatorField.CTIME, KerberosTime.class),
            new ExplicitField(AuthenticatorField.SUBKEY, EncryptionKey.class),
            new ExplicitField(AuthenticatorField.SEQ_NUMBER, Asn1Integer.class),
            new ExplicitField(AuthenticatorField.AUTHORIZATION_DATA, AuthorizationData.class)
    };

    /**
     * Creates a new instance of an Authenticator
     */
    public Authenticator() {
        super(TAG, fieldInfos);
        
        // Default to Version 5
        setAuthenticatorVno(KrbConstant.KRB_V5);
    }

    /**
     * @return The Authenticator Version Number
     */
    public int getAuthenticatorVno() {
        return getFieldAsInt(AuthenticatorField.AUTHENTICATOR_VNO);
    }

    /**
     * Sets the Authenticator version
     * @param authenticatorVno The Authenticator version to store
     */
    public void setAuthenticatorVno(int authenticatorVno) {
        setFieldAsInt(AuthenticatorField.AUTHENTICATOR_VNO, authenticatorVno);
    }

    /**
     * @return The Client Realm
     */
    public String getCrealm() {
        return getFieldAsString(AuthenticatorField.CREALM);
    }

    /**
     * Sets the Client Realm
     * @param crealm The Client Realm to store
     */
    public void setCrealm(String crealm) {
        setFieldAsString(AuthenticatorField.CREALM, crealm);
    }

    /**
     * @return The client Principal's name
     */
    public PrincipalName getCname() {
        return getFieldAs(AuthenticatorField.CNAME, PrincipalName.class);
    }

    /**
     * Sets the Client Principal's name
     * @param cname The Client Principal's name to store
     */
    public void setCname(PrincipalName cname) {
        setFieldAs(AuthenticatorField.CNAME, cname);
    }

    /**
     * @return application data checksum
     */
    public CheckSum getCksum() {
        return getFieldAs(AuthenticatorField.CKSUM, CheckSum.class);
    }

    /**
     * Sets the application data checksum
     * @param cksum The application data checksum to store
     */
    public void setCksum(CheckSum cksum) {
        setFieldAs(AuthenticatorField.CKSUM, cksum);
    }

    /**
     * @return The microsecond part of the client's timestamp
     */
    public int getCusec() {
        return getFieldAsInt(AuthenticatorField.CUSEC);
    }

    /**
     * Sets the The microsecond part of the client's timestamp
     * @param cusec The microsecond part of the client's timestamp to store
     */
    public void setCusec(int cusec) {
        setFieldAsInt(AuthenticatorField.CUSEC, cusec);
    }

    /**
     * @return The client's host current time
     */
    public KerberosTime getCtime() {
        return getFieldAsTime(AuthenticatorField.CTIME);
    }

    /**
     * Sets the client's host current time
     * @param ctime The client's host current time to store
     */
    public void setCtime(KerberosTime ctime) {
        setFieldAs(AuthenticatorField.CTIME, ctime);
    }

    /**
     * @return The client's encryption key
     */
    public EncryptionKey getSubKey() {
        return getFieldAs(AuthenticatorField.SUBKEY, EncryptionKey.class);
    }

    /**
     * Sets the client's encryption key
     * @param subKey The client's encryption key to store
     */
    public void setSubKey(EncryptionKey subKey) {
        setFieldAs(AuthenticatorField.SUBKEY, subKey);
    }

    /**
     * @return The initial sequence number
     */
    public int getSeqNumber() {
        return getFieldAsInt(AuthenticatorField.SEQ_NUMBER);
    }

    /**
     * Sets the initial sequence number
     * @param seqNumber The initial sequence number to store
     */
    public void setSeqNumber(Integer seqNumber) {
        setFieldAsInt(AuthenticatorField.SEQ_NUMBER, seqNumber);
    }

    /**
     * @return The stored Authorization-Data
     */
    public AuthorizationData getAuthorizationData() {
        return getFieldAs(AuthenticatorField.AUTHORIZATION_DATA, AuthorizationData.class);
    }

    /**
     * Sets the stored Authorization-Data
     * @param authorizationData The Authorization-Data to store
     */
    public void setAuthorizationData(AuthorizationData authorizationData) {
        setFieldAs(AuthenticatorField.AUTHORIZATION_DATA, authorizationData);
    }
}
