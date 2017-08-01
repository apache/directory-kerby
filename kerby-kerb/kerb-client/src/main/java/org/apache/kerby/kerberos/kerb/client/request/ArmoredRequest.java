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
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.preauth.KrbFastRequestState;
import org.apache.kerby.kerberos.kerb.common.CheckSumUtil;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.crypto.fast.FastUtil;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.ap.ApOptions;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.fast.ArmorType;
import org.apache.kerby.kerberos.kerb.type.fast.KrbFastArmor;
import org.apache.kerby.kerberos.kerb.type.fast.KrbFastArmoredReq;
import org.apache.kerby.kerberos.kerb.type.fast.KrbFastReq;
import org.apache.kerby.kerberos.kerb.type.fast.PaFxFastRequest;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;

import java.io.File;
import java.io.IOException;

public class ArmoredRequest {

    private Credential credential;
    private EncryptionKey subKey;
    private EncryptionKey armorCacheKey;
    private KdcRequest kdcRequest;

    public ArmoredRequest(KdcRequest kdcRequest) {
        this.kdcRequest = kdcRequest;
    }

    public void process() throws KrbException {
        KdcReq kdcReq = kdcRequest.getKdcReq();
        KrbFastRequestState state = kdcRequest.getFastRequestState();
        fastAsArmor(state, kdcRequest.getArmorKey(), subKey, credential, kdcReq);
        kdcRequest.setFastRequestState(state);
        kdcRequest.setOuterRequestBody(KrbCodec.encode(state.getFastOuterRequest()));
        kdcReq.getPaData().addElement(makeFastEntry(state, kdcReq,
            kdcRequest.getOuterRequestBody()));
    }

    protected void preauth() throws KrbException {
        KOptions preauthOptions = getPreauthOptions();
        getCredential(preauthOptions);
        armorCacheKey = getArmorCacheKey(credential);

        subKey = getSubKey(armorCacheKey.getKeyType());
        EncryptionKey armorKey = makeArmorKey(subKey, armorCacheKey);
        kdcRequest.getFastRequestState().setArmorKey(armorKey);
    }

    private void getCredential(KOptions kOptions) throws KrbException {

        if (kOptions.contains(KrbOption.ARMOR_CACHE)) {
            String ccache = kOptions.getStringOption(KrbOption.ARMOR_CACHE);
            credential = getCredentialFromFile(ccache);
        } else if (kOptions.contains(KrbOption.TGT)) {
            TgtTicket tgt = (TgtTicket) kOptions.getOptionValue(KrbOption.TGT);
            credential = new Credential(tgt);
        }
    }

    public KOptions getPreauthOptions() {
        KOptions results = new KOptions();

        KOptions krbOptions = kdcRequest.getRequestOptions();
        if (krbOptions.contains(KrbOption.ARMOR_CACHE)) {
            results.add(krbOptions.getOption(KrbOption.ARMOR_CACHE));
        } else if (krbOptions.contains(KrbOption.TGT)) {
            results.add(krbOptions.getOption(KrbOption.TGT));
        }
        return results;
    }

    public EncryptionKey getClientKey() throws KrbException {
        return kdcRequest.getFastRequestState().getArmorKey();
    }

    public EncryptionKey getArmorCacheKey() {
        return armorCacheKey;
    }

    private Credential getCredentialFromFile(String ccache) throws KrbException {
        File ccacheFile = new File(ccache);
        CredentialCache cc = null;
        try {
            cc = resolveCredCache(ccacheFile);
        } catch (IOException e) {
            throw new KrbException("Failed to load armor cache file");
        }
        // TODO: get the right credential.
        return cc.getCredentials().iterator().next();
    }

    private static CredentialCache resolveCredCache(File ccacheFile) throws IOException {
        CredentialCache cc = new CredentialCache();
        cc.load(ccacheFile);

        return cc;
    }

    private void fastAsArmor(KrbFastRequestState state,
                                                  EncryptionKey armorKey, EncryptionKey subKey,
                                                  Credential credential, KdcReq kdcReq)
        throws KrbException {
        state.setArmorKey(armorKey);
        state.setFastArmor(fastArmorApRequest(subKey, credential));
        KdcReq fastOuterRequest = new AsReq();
        fastOuterRequest.setReqBody(kdcReq.getReqBody());
        fastOuterRequest.setPaData(null);
        state.setFastOuterRequest(fastOuterRequest);
    }

    private PaDataEntry makeFastEntry(KrbFastRequestState state, KdcReq kdcReq,
                                             byte[] outerRequestBody) throws KrbException {

        KrbFastReq fastReq = new KrbFastReq();
        fastReq.setKdcReqBody(kdcReq.getReqBody());
        fastReq.setFastOptions(state.getFastOptions());

        PaFxFastRequest paFxFastRequest = new PaFxFastRequest();

        KrbFastArmoredReq armoredReq = new KrbFastArmoredReq();
        armoredReq.setArmor(state.getFastArmor());
        CheckSum reqCheckSum = CheckSumUtil.makeCheckSumWithKey(CheckSumType.NONE,
            outerRequestBody, state.getArmorKey(), KeyUsage.FAST_REQ_CHKSUM);
        armoredReq.setReqChecksum(reqCheckSum);
        armoredReq.setEncryptedFastReq(EncryptionUtil.seal(fastReq, state.getArmorKey(), KeyUsage.FAST_ENC));
        paFxFastRequest.setFastArmoredReq(armoredReq);

        PaDataEntry paDataEntry = new PaDataEntry();
        paDataEntry.setPaDataType(PaDataType.FX_FAST);
        paDataEntry.setPaDataValue(KrbCodec.encode(paFxFastRequest));

        return paDataEntry;
    }

    private KrbFastArmor fastArmorApRequest(EncryptionKey subKey, Credential credential)
        throws KrbException {
        KrbFastArmor fastArmor = new KrbFastArmor();
        fastArmor.setArmorType(ArmorType.ARMOR_AP_REQUEST);
        ApReq apReq = makeApReq(subKey, credential);
        fastArmor.setArmorValue(KrbCodec.encode(apReq));
        return fastArmor;
    }

    private ApReq makeApReq(EncryptionKey subKey, Credential credential)
        throws KrbException {
        ApReq apReq = new ApReq();
        ApOptions apOptions = new ApOptions();
        apReq.setApOptions(apOptions);
        Ticket ticket = credential.getTicket();
        apReq.setTicket(ticket);
        Authenticator authenticator = makeAuthenticator(credential, subKey);
        apReq.setAuthenticator(authenticator);
        EncryptedData authnData = EncryptionUtil.seal(authenticator,
            credential.getKey(), KeyUsage.AP_REQ_AUTH);
        apReq.setEncryptedAuthenticator(authnData);
        return apReq;
    }

    /**
     * Prepare FAST armor key.
     * @return
     * @throws KrbException
     */
    private EncryptionKey makeArmorKey(EncryptionKey subKey, EncryptionKey armorCacheKey)
        throws KrbException {
        EncryptionKey armorKey = FastUtil.makeArmorKey(subKey, armorCacheKey);
        return armorKey;
    }

    private EncryptionKey getSubKey(EncryptionType type) throws KrbException {
        return EncryptionHandler.random2Key(type);
    }

    /**
     * Get armor cache key.
     * @return armor cache key
     * @throws KrbException
     */
    private EncryptionKey getArmorCacheKey(Credential credential) throws KrbException {
        EncryptionKey armorCacheKey = credential.getKey();

        return armorCacheKey;
    }

    protected Authenticator makeAuthenticator(Credential credential,
                                              EncryptionKey subKey) throws KrbException {
        Authenticator authenticator = new Authenticator();
        authenticator.setAuthenticatorVno(5);
        authenticator.setCname(credential.getClientName());
        authenticator.setCrealm(credential.getClientRealm());
        authenticator.setCtime(KerberosTime.now());
        authenticator.setCusec(0);
        authenticator.setSubKey(subKey);

        KdcReqBody reqBody = kdcRequest.getReqBody(null);
        CheckSum checksum = CheckSumUtil.seal(reqBody, null,
            subKey, KeyUsage.TGS_REQ_AUTH_CKSUM);
        authenticator.setCksum(checksum);

        return authenticator;
    }
}
