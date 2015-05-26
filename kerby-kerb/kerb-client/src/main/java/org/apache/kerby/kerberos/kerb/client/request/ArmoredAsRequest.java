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
package org.apache.kerby.kerberos.kerb.client.request;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.preauth.KrbFastRequestState;
import org.apache.kerby.kerberos.kerb.common.CheckSumUtil;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.crypto.fast.FastUtil;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.ap.ApOptions;
import org.apache.kerby.kerberos.kerb.spec.ap.ApReq;
import org.apache.kerby.kerberos.kerb.spec.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.spec.base.CheckSum;
import org.apache.kerby.kerberos.kerb.spec.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.fast.ArmorType;
import org.apache.kerby.kerberos.kerb.spec.fast.KrbFastArmor;
import org.apache.kerby.kerberos.kerb.spec.fast.KrbFastArmoredReq;
import org.apache.kerby.kerberos.kerb.spec.fast.KrbFastReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;

import java.io.File;
import java.io.IOException;

/**
 * This initiates an armor protected AS-REQ using FAST/Pre-auth.
 */
public abstract class ArmoredAsRequest extends AsRequest {

    private Credential credential;
    private EncryptionKey subKey;

    public ArmoredAsRequest(KrbContext context) {
        super(context);
    }

    @Override
    protected void preauth() throws KrbException {
        makeArmorKey();
        super.preauth();
    }

    @Override
    public void process() throws KrbException {
        super.process();
        fastAsArmor();
        getKdcReq().getPaData().addElement(makeFastEntry());
    }

    @Override
    public KOptions getPreauthOptions() {
        KOptions results = new KOptions();

        KOptions krbOptions = getKrbOptions();
        results.add(krbOptions.getOption(KrbOption.ARMOR_CACHE));

        return results;
    }

    @Override
    public EncryptionKey getClientKey() throws KrbException {
        return getFastRequestState().getArmorKey();
    }

    /**
     * Prepare FAST armor key.
     * @return
     * @throws KrbException
     */
    protected EncryptionKey makeArmorKey() throws KrbException {
        getCredential();

        EncryptionKey armorCacheKey = getArmorCacheKey();
        subKey = getSubKey(armorCacheKey.getKeyType());
        EncryptionKey armorKey = FastUtil.cf2(subKey, "subkeyarmor",
            armorCacheKey, "ticketarmor");
        getFastRequestState().setArmorKey(armorKey);
        return armorKey;
    }

    protected EncryptionKey getSubKey(EncryptionType type) throws KrbException {
        return EncryptionHandler.random2Key(type);
    }

    /**
     * Get armor cache key.
     * @return armor cache key
     * @throws KrbException
     */
    protected EncryptionKey getArmorCacheKey() throws KrbException {
        EncryptionKey armorCacheKey = credential.getKey();

        return armorCacheKey;
    }

    private void getCredential() throws KrbException {
        KOptions preauthOptions = getPreauthOptions();
        String ccache = preauthOptions.getStringOption(KrbOption.ARMOR_CACHE);
        File ccacheFile = new File(ccache);
        CredentialCache cc = null;
        try {
            cc = resolveCredCache(ccacheFile);
        } catch (IOException e) {
            throw new KrbException("Failed to load armor cache file");
        }
        // TODO: get the right credential.
        this.credential = cc.getCredentials().iterator().next();
    }

    public void fastAsArmor() throws KrbException {
        KrbFastRequestState state = getFastRequestState();
        state.setArmorKey(getArmorKey());
        state.setFastArmor(fastArmorApRequest(subKey, credential));
        KdcReq fastOuterRequest = new AsReq();
        fastOuterRequest.setReqBody(getKdcReq().getReqBody());
        fastOuterRequest.setPaData(null);
        state.setFastOuterRequest(fastOuterRequest);
        setFastRequestState(state);

        setOuterRequestBody(state.getFastOuterRequest().encode());
    }

    private PaDataEntry makeFastEntry() throws KrbException {
        KrbFastRequestState state = getFastRequestState();

        KrbFastReq fastReq = new KrbFastReq();
        fastReq.setKdcReqBody(getKdcReq().getReqBody());
        fastReq.setFastOptions(state.getFastOptions());

        KrbFastArmoredReq armoredReq = new KrbFastArmoredReq();
        armoredReq.setArmor(state.getFastArmor());
        CheckSum reqCheckSum = CheckSumUtil.makeCheckSumWithKey(CheckSumType.NONE,
            getOuterRequestBody(), state.getArmorKey(), KeyUsage.FAST_REQ_CHKSUM);
        armoredReq.setReqChecksum(reqCheckSum);
        armoredReq.setEncryptedFastReq(EncryptionUtil.seal(fastReq, state.getArmorKey(),
            KeyUsage.FAST_ENC));

        PaDataEntry paDataEntry = new PaDataEntry();
        paDataEntry.setPaDataType(PaDataType.FX_FAST);
        paDataEntry.setPaDataValue(armoredReq.encode());

        return paDataEntry;
    }

     public static KrbFastArmor fastArmorApRequest(EncryptionKey subKey, Credential credential)
        throws KrbException {
        KrbFastArmor fastArmor = new KrbFastArmor();
        fastArmor.setArmorType(ArmorType.ARMOR_AP_REQUEST);
        ApReq apReq = makeApReq(subKey, credential);
        fastArmor.setArmorValue(apReq.encode());
        return fastArmor;
    }

    private static ApReq makeApReq(EncryptionKey subKey, Credential credential)
        throws KrbException {
        ApReq apReq = new ApReq();
        ApOptions apOptions = new ApOptions();
        apReq.setApOptions(apOptions);
        Ticket ticket = credential.getTicket();
        apReq.setTicket(ticket);
        Authenticator authenticator = makeAuthenticator(credential.getClientName(),
            credential.getClientRealm(), subKey);
        apReq.setAuthenticator(authenticator);
        EncryptedData authnData = EncryptionUtil.seal(authenticator,
            credential.getKey(), KeyUsage.AP_REQ_AUTH);
        apReq.setEncryptedAuthenticator(authnData);
        return apReq;
    }
}