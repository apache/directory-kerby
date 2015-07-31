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
package org.apache.kerby.kerberos.kerb.client.preauth.builtin;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.preauth.AbstractPreauthPlugin;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequestWithTgt;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.builtin.TgtPreauthMeta;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

public class TgtPreauth extends AbstractPreauthPlugin {

    public TgtPreauth() {
        super(new TgtPreauthMeta());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

        outPadata.addElement(makeEntry(kdcRequest));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean process(KdcRequest kdcRequest,
                           PluginRequestContext requestContext,
                           PaDataEntry inPadata,
                           PaData outPadata) throws KrbException {

        outPadata.addElement(makeEntry(kdcRequest));

        return true;
    }

    /**
     * Make padata entry.
     *
     * @param kdcRequest The kdc request
     * @return PaDataEntry to be made.
     */
    private PaDataEntry makeEntry(KdcRequest kdcRequest) throws KrbException {

        TgsRequestWithTgt tgsRequest = (TgsRequestWithTgt) kdcRequest;

        PaDataEntry paEntry = new PaDataEntry();
        paEntry.setPaDataType(PaDataType.TGS_REQ);
        paEntry.setPaDataValue(tgsRequest.getApReq().encode());

        return paEntry;
    }
}
