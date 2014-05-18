package org.haox.kerb.common.handler;

import org.haox.kerb.common.event.TransportEvent;

public interface TransportHandler extends KrbHandler {

    public void handleTransport(TransportEvent event);

}
