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
package org.apache.kerby.kerberos.kerb.client.preauth;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

import java.util.ArrayList;
import java.util.List;

public class PreauthContext {
    private boolean preauthRequired = true;
    private PaData inputPaData;
    private PaData outputPaData;
    private PaData errorPaData;
    private UserResponser userResponser = new UserResponser();
    private PaDataType selectedPaType;
    private PaDataType allowedPaType;
    private List<PaDataType> triedPaTypes = new ArrayList<PaDataType>(1);
    private List<PreauthHandle> handles = new ArrayList<PreauthHandle>(5);

    public PreauthContext() {
        this.selectedPaType = PaDataType.NONE;
        this.allowedPaType = PaDataType.NONE;
        this.outputPaData = new PaData();
    }

    public boolean isPreauthRequired() {
        return preauthRequired;
    }

    public void setPreauthRequired(boolean preauthRequired) {
        this.preauthRequired = preauthRequired;
    }

    public UserResponser getUserResponser() {
        return userResponser;
    }

    public boolean isPaTypeAllowed(PaDataType paType) {
        return (allowedPaType == PaDataType.NONE ||
                allowedPaType == paType);
    }

    public PaData getOutputPaData() throws KrbException {
        return outputPaData;
    }

    public boolean hasInputPaData() {
        return  (inputPaData != null && ! inputPaData.isEmpty());
    }

    public PaData getInputPaData() {
        return inputPaData;
    }

    public void setInputPaData(PaData inputPaData) {
        this.inputPaData = inputPaData;
    }

    public PaData getErrorPaData() {
        return errorPaData;
    }

    public void setErrorPaData(PaData errorPaData) {
        this.errorPaData = errorPaData;
    }

    public void setAllowedPaType(PaDataType paType) {
        this.allowedPaType = paType;
    }

    public List<PreauthHandle> getHandles() {
        return handles;
    }

    public PaDataType getAllowedPaType() {
        return allowedPaType;
    }

    public boolean checkAndPutTried(PaDataType paType) {
        for (PaDataType pt : triedPaTypes) {
            if (pt == paType) {
                return true;
            }
        }
        triedPaTypes.add(paType);
        return false;
    }
}
