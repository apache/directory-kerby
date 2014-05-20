package org.haox.kerb.event;

import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.transport.Transport;

public class NewOutboundKrbMessageEvent extends KrbMessageEvent {

    public NewOutboundKrbMessageEvent(Transport transport, KrbMessage message) {
        super(transport, message, EventType.NEW_OUTBOUND_KRBMESSAGE);
    }
}
