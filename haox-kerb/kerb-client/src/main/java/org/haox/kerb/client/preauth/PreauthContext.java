package org.haox.kerb.client.preauth;

import org.haox.kerb.KrbException;
import org.haox.kerb.spec.pa.PaData;
import org.haox.kerb.spec.pa.PaDataType;

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
