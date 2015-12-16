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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit;


import org.apache.kerby.kerberos.kerb.crypto.dh.DhGroup;

import javax.crypto.spec.DHParameterSpec;


/**
 * Client configuration settings.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class ClientConfiguration {
    /**
     * The location of the user certificate.
     */
    private String certificatePath;

    /**
     * The CMS types to use.
     */
    private String cmsType;

    /**
     * Whether or not to use Diffie-Hellman.  The alternative is the "public key"
     * method.
     */
    private boolean isDhUsed = true;

    /**
     * The Diffie-Hellman group to use.
     */
    private DHParameterSpec dhGroup = DhGroup.MODP_GROUP2;

    /**
     * Whether or not to reuse Diffie-Hellman keys.
     */
    private boolean isDhKeysReused;


    /**
     * @return the certificatePath
     */
    public String getCertificatePath() {
        return certificatePath;
    }


    /**
     * @param certificatePath the certificatePath to set
     */
    public void setCertificatePath(String certificatePath) {
        this.certificatePath = certificatePath;
    }


    /**
     * @return the cmsType
     */
    public String getCmsType() {
        return cmsType;
    }


    /**
     * @param cmsType the cmsType to set
     */
    public void setCmsType(String cmsType) {
        this.cmsType = cmsType;
    }


    /**
     * @return the isDhUsed
     */
    public boolean isDhUsed() {
        return isDhUsed;
    }


    /**
     * @param isDhUsed the isDhUsed to set
     */
    public void setDhUsed(boolean isDhUsed) {
        this.isDhUsed = isDhUsed;
    }


    /**
     * @return the dhGroup
     */
    public DHParameterSpec getDhGroup() {
        return dhGroup;
    }


    /**
     * @param dhGroup the dhGroup to set
     */
    public void setDhGroup(DHParameterSpec dhGroup) {
        this.dhGroup = dhGroup;
    }


    /**
     * @return the isDhKeysReused
     */
    public boolean isDhKeysReused() {
        return isDhKeysReused;
    }


    /**
     * @param isDhKeysReused the isDhKeysReused to set
     */
    public void setDhKeysReused(boolean isDhKeysReused) {
        this.isDhKeysReused = isDhKeysReused;
    }
}
