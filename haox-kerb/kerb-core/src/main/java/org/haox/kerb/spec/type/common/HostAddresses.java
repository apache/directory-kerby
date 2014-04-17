package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceOfType;

import java.util.List;

/**
 -- NOTE: HostAddresses is always used as an OPTIONAL field and
 -- should not be empty.
 HostAddresses   -- NOTE: subtly different from rfc1510,
 -- but has a value mapping and encodes the same
 ::= SEQUENCE OF HostAddress
 */
public interface HostAddresses extends SequenceOfType {
    public static Class<? extends KrbType> ElementType =  HostAddress.class;

    public List<HostAddress> getAddresses();

    public void setAddresses(List<HostAddress> addresses);
}
