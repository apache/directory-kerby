package org.haox.kerb.handler;

import org.haox.kerb.event.TransportEvent;

public interface TransportHandler extends Handler {

    public void handleTransport(TransportEvent event);

}
