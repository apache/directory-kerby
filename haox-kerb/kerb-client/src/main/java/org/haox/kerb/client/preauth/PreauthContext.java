package org.haox.kerb.client.preauth;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.ArrayList;
import java.util.List;

public class PreauthContext {
    private boolean preauthRequired = true;
    private PaData inputPaData;
    private PaData preauthData;
    private UserResponser userResponser = new UserResponser();
    private PaDataType selectedPreauthType;
    private PaDataType allowedPreauthType;
    private List<PaDataType> tried = new ArrayList<PaDataType>(1);
    private List<PreauthHandle> handles = new ArrayList<PreauthHandle>(5);

    public PreauthContext() {
        this.selectedPreauthType = PaDataType.NONE;
        this.allowedPreauthType = PaDataType.NONE;
        this.preauthData = new PaData();
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
        return (allowedPreauthType == PaDataType.NONE ||
                allowedPreauthType == paType);
    }

    public PaData getPreauthData() throws KrbException {
        return preauthData;
    }

    public PaData getInputPaData() {
        return inputPaData;
    }

    public void setInputPaData(PaData inputPaData) {
        this.inputPaData = inputPaData;
    }

    public void setAllowedPreauth(PaDataType paType) {
        this.allowedPreauthType = paType;
    }

    public List<PreauthHandle> getHandles() {
        return handles;
    }
}
