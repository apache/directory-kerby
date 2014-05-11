package org.haox.kerb.client;

import org.haox.kerb.spec.type.common.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class KrbErrorUtil {

    public static List<EncryptionType> getEtypes(KrbError error) throws IOException {
        MethodData methodData = new MethodData();
        methodData.decode(error.getEdata());

        for( PaDataEntry pd : methodData.getElements()) {
            if( pd.getPaDataType() == PaDataType.ETYPE_INFO2 ) {
                return getEtypes2(pd.getPaDataValue());
            }
            else if( pd.getPaDataType() == PaDataType.ETYPE_INFO ) {
                return getEtypes(pd.getPaDataValue());
            }
        }
        return Collections.EMPTY_LIST;
    }

    private static List<EncryptionType> getEtypes(byte[] data) throws IOException {
        EtypeInfo info = new EtypeInfo();
        info.decode(data);
        List<EncryptionType> results = new ArrayList<EncryptionType>();
        for( EtypeInfoEntry entry : info.getElements() ) {
            results.add(entry.getEtype());
        }
        return results;
    }

    private static List<EncryptionType> getEtypes2(byte[] data) throws IOException {
        EtypeInfo2 info2 = new EtypeInfo2();
        info2.decode(data);
        List<EncryptionType> results = new ArrayList<EncryptionType>();
        for( EtypeInfo2Entry entry : info2.getElements() ) {
            results.add(entry.getEtype());
        }
        return results;
    }
}
