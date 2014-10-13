package org.haox.kerb.client.event;

import org.haox.event.Event;
import org.haox.kerb.client.as.AsRequest;
import org.haox.kerb.client.as.AsResponse;
import org.haox.kerb.client.tgs.TgsRequest;
import org.haox.kerb.client.tgs.TgsResponse;

public class KrbClientEvent {

    public static Event createTgtIntentEvent(AsRequest asRequest) {
        return new Event(KrbClientEventType.TGT_INTENT, asRequest);
    }

    public static Event createTktIntentEvent(TgsRequest tgsRequest) {
        return new Event(KrbClientEventType.TKT_INTENT, tgsRequest);
    }

    public static Event createTgtResultEvent(AsResponse asResponse) {
        return new Event(KrbClientEventType.TGT_RESULT, asResponse);
    }

    public static Event createTktResultEvent(TgsResponse tgsResponse) {
        return new Event(KrbClientEventType.TKT_RESULT, tgsResponse);
    }
}
