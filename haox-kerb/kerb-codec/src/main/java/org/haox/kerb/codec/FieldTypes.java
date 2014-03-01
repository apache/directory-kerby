package org.haox.kerb.codec;

import org.haox.kerb.spec.type.KrbType;

import java.util.ArrayList;
import java.util.List;

public class FieldTypes {
    Class<? extends KrbType>[] fieldTypes;
    //List<Class<? extends KrbType>> fieldTypes;

    public FieldTypes(int fieldsNum) {
        //fieldTypes = new ArrayList<Class <? extends KrbType>>(fieldsNum);
    }

    public FieldTypes(Class<? extends KrbType> ... types) {
        List<Class<? extends KrbType>> typesList = new ArrayList<Class <? extends KrbType>>(types.length);
        for (Class<? extends KrbType> type : types) {
            typesList.add(type);
        }
        this.fieldTypes = (Class<? extends KrbType>[]) typesList.toArray();
        typesList.clear();
    }

    public Class<? extends KrbType> get(int index) {
        return this.fieldTypes[index];
    }

    public void add(Class<? extends KrbType> fieldType) {
        //this.fieldTypes.add(fieldType);
    }
}
