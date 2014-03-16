package org.haox.kerb.spec;

import org.haox.kerb.spec.type.*;
import org.haox.kerb.spec.type.common.KrbTime;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KrbTypes {
    private static Map<Class<? extends KrbType>, Class<? extends KrbType>> entries =
            new HashMap<Class<? extends KrbType>, Class<? extends KrbType>>();

    public static void implement(Class<? extends KrbType> inf, Class<? extends KrbType> impl) {
        entries.put(inf, impl);
    }

    public static Class<? extends KrbType> getImpl(Class<? extends KrbType> inf) throws KrbException {
        Class<? extends KrbType> impl = entries.get(inf);
        if (impl == null) {
            String fullName = inf.getCanonicalName();
            String simpleName = inf.getSimpleName();
            String fullClassName = fullName.replace(simpleName, "impl." + simpleName + "Impl");
            try {
                Class<?> aClass = inf.getClassLoader().loadClass(fullClassName);
                try {
                    impl = (Class<? extends KrbType>) aClass;
                    entries.put(inf, impl);
                } catch (ClassCastException e) {
                    KrbThrow.out(KrbTypeMessageCode.INVALID_KRB_IMPL, e);
                }
            } catch (ClassNotFoundException e) { }
        }
        if (impl == null) {
            KrbThrow.out(KrbTypeMessageCode.NO_IMPL_FOUND, "for interface " + inf.getCanonicalName());
        }

        return impl;
    }

    public static KrbInteger makeInteger(KrbEnum eValue) throws KrbException {
        return makeInteger(eValue.getValue());
    }

    public static KrbInteger makeInteger(int value) throws KrbException {
        KrbInteger result = KrbFactory.create(KrbInteger.class);
        result.setValue(BigInteger.valueOf(value));
        return result;
    }

    public static KrbString makeString(String value) throws KrbException {
        KrbString result = KrbFactory.create(KrbString.class);
        result.setValue(value);
        return result;
    }

    public static KrbStrings makeStrings(List<String> strings) throws KrbException {
        KrbStrings result = KrbFactory.create(KrbStrings.class);
        result.setValues(strings);
        return result;
    }

    public static KrbOctetString makeOctetString(byte[] octets) throws KrbException {
        KrbOctetString value = KrbFactory.create(KrbOctetString.class);
        value.setValue(octets);
        return value;
    }

    public static KrbTime makeTime(int value) throws KrbException {
        KrbTime result = KrbFactory.create(KrbTime.class);
        result.setValue(value);
        return result;
    }

}
