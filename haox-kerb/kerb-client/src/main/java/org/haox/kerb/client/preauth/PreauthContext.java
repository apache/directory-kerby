package org.haox.kerb.client.preauth;

import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.ArrayList;
import java.util.List;

public class PreauthContext {

    public PreauthCallback preauthCallback;
    public ResponseItems responseItems = new ResponseItems();
    public List<PaDataType> tried = new ArrayList<PaDataType>(1);
    public List<PreauthHandle> handles = new ArrayList<PreauthHandle>(5);
}
