package org.haox.kerb.transport;

import org.haox.kerb.dispatch.Dispatcher;
import org.haox.kerb.event.NewInboundMessageEvent;
import org.haox.kerb.event.NewOutboundMessageEvent;
import org.haox.kerb.message.Message;

public abstract class Transport {
    private boolean isActive;
    private Dispatcher dispatcher;

    public Transport(boolean isActive) {
        this.isActive = isActive;
    }

    public void sendMessage(Message message) {
        handleOutboundMessage(message);
    }

    public void onReadable() {

    }

    public void onWriteable() {

    }

    private void handleInboundMessage(Message message) {
        dispatcher.dispatch(new NewInboundMessageEvent(this, message));
    }

    private void handleOutboundMessage(Message message) {
        dispatcher.dispatch(new NewOutboundMessageEvent(this, message));
    }
}
