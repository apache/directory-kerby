package org.haox.kerb.common.transport;

import org.haox.kerb.common.dispatch.KrbDispatcher;
import org.haox.kerb.common.event.MessageEvent;
import org.haox.kerb.spec.type.common.KrbMessage;

public abstract class KrbTransport {
    private boolean isActive;
    private KrbDispatcher dispatcher;

    public KrbTransport(boolean isActive) {
        this.isActive = isActive;
    }

    public void sendMessage(KrbMessage message) {
        handleOutboundMessage(message);
    }

    public void onReadable() {

    }

    public void onWriteable() {

    }

    private void handleInboundMessage(KrbMessage message) {
        dispatcher.dispatch(new MessageEvent(this, message));
    }

    private void handleOutboundMessage(KrbMessage message) {

    }
}
