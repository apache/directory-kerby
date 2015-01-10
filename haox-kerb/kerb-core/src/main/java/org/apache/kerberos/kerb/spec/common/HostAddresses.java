package org.apache.kerberos.kerb.spec.common;

import org.apache.kerberos.kerb.spec.KrbSequenceOfType;

import java.net.InetAddress;

/**
 -- NOTE: HostAddresses is always used as an OPTIONAL field and
 -- should not be empty.
 HostAddresses   -- NOTE: subtly different from rfc1510,
 -- but has a value mapping and encodes the same
 ::= SEQUENCE OF HostAddress
 */
public class HostAddresses extends KrbSequenceOfType<HostAddress> {

    public boolean contains(InetAddress address) {
        for (HostAddress hostAddress : getElements()) {
            if (hostAddress.equalsWith(address)) {
                return true;
            }
        }
        return false;
    }
}
