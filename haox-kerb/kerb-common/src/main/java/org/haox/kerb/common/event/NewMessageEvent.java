package org.haox.kerb.common.event;

import org.haox.kerb.common.transport.KrbTransport;
import org.haox.kerb.spec.type.common.KrbMessage;

public class NewMessageEvent extends MessageEvent {

    public NewMessageEvent(KrbTransport transport, KrbMessage message) {
        super(transport, message, EventType.NEW_MESSAGE);
    }
}
