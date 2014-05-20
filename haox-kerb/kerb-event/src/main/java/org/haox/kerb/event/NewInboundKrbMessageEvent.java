package org.haox.kerb.event;

import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.transport.Transport;

public class NewInboundKrbMessageEvent extends KrbMessageEvent {

    public NewInboundKrbMessageEvent(Transport transport, KrbMessage message) {
        super(transport, message, EventType.NEW_INBOUND_KRBMESSAGE);
    }
}
