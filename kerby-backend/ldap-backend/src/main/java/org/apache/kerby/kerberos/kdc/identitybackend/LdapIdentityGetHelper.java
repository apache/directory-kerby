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
package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.util.GeneralizedTime;
import org.apache.directory.shared.kerberos.KerberosAttribute;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class LdapIdentityGetHelper {
    private Entry entry;
    public LdapIdentityGetHelper(Entry entry) {
        this.entry = entry;
    }

    /**
     * Get principal name.
     * @throws LdapInvalidAttributeValueException e
     * @return principal name
     */
    public PrincipalName getPrincipalName() throws LdapInvalidAttributeValueException {
        String principalNameStr = entry.get(KerberosAttribute.KRB5_PRINCIPAL_NAME_AT).getString();
        PrincipalName principalName = new PrincipalName(principalNameStr);
        return principalName;
    }

    /**
     * Get key version.
     * @throws LdapInvalidAttributeValueException e
     * @return key version
     */
    public int getKeyVersion() throws LdapInvalidAttributeValueException {
        String keyVersionStr = entry.get(KerberosAttribute.KRB5_KEY_VERSION_NUMBER_AT).getString();
        int keyVersion = Integer.parseInt(keyVersionStr);
        return keyVersion;
    }

    /**
     * Get keys.
     * @throws IOException e
     * @return keys
     */
    public List<EncryptionKey> getKeys() throws IOException {
        Iterator<Value<?>> iterator1 = entry.get(KerberosAttribute.KRB5_KEY_AT).iterator();
        List<EncryptionKey> keys = new ArrayList<>();
        while (iterator1.hasNext()) {
            byte[] encryKey = iterator1.next().getBytes();
            EncryptionKey key = new EncryptionKey();
            key.decode(encryKey);
            key.setKvno(1); // TODO: kvno should be correctly stored and retrieved
            keys.add(key);
        }
        return keys;
    }

    /**
     * Get created time.
     * @throws LdapInvalidAttributeValueException e
     * @throws ParseException e
     * @return created time
     */
    public KerberosTime getCreatedTime() throws LdapInvalidAttributeValueException,
            ParseException {
        String createTime = entry.get("createTimestamp").getString();
        return createKerberosTime(createTime);
    }

    /**
     * Get expire time.
     * @throws LdapInvalidAttributeValueException e
     * @throws ParseException e
     * @return the expire time
     */
    public KerberosTime getExpireTime() throws LdapInvalidAttributeValueException,
            ParseException {
        String expirationTime = entry.get(KerberosAttribute.KRB5_ACCOUNT_EXPIRATION_TIME_AT).getString();
        return createKerberosTime(expirationTime);
    }

    /**
     * Get whether disabled.
     * @throws LdapInvalidAttributeValueException e
     * @return whether this krb5 account is disabled
     */
    public boolean getDisabled() throws LdapInvalidAttributeValueException {
        String disabled = entry.get(KerberosAttribute.KRB5_ACCOUNT_DISABLED_AT).getString();
        return Boolean.parseBoolean(disabled);
    }

    /**
     * Get kdc flags.
     * @throws LdapInvalidAttributeValueException e
     * @return kdc flags
     */
    public int getKdcFlags() throws LdapInvalidAttributeValueException {
        String krb5KDCFlags = entry.get("krb5KDCFlags").getString();
        return Integer.parseInt(krb5KDCFlags);
    }

    /**
     * Get whether locked.
     * @throws LdapInvalidAttributeValueException e
     * @return whether the krb5 account is locked
     */
    public boolean getLocked() throws LdapInvalidAttributeValueException {
        String lockedOut = entry.get(KerberosAttribute.KRB5_ACCOUNT_LOCKEDOUT_AT).getString();
        return Boolean.parseBoolean(lockedOut);
    }

    /**
     * Create kerberos time.
     */
    private KerberosTime createKerberosTime(String generalizedTime)
            throws ParseException {
        long time = new GeneralizedTime(generalizedTime).getTime();
        return new KerberosTime(time);
    }
}