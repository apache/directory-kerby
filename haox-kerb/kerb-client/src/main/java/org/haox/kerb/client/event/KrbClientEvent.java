package org.haox.kerb.client.event;

import org.haox.event.Event;
import org.haox.kerb.client.AsRequest;
import org.haox.kerb.client.TgsRequest;

public class KrbClientEvent {

    public static Event createTgtIntentEvent(AsRequest asRequest) {
        return new Event(KrbClientEventType.TGT_INTENT, asRequest);
    }

    public static Event createTktIntentEvent(TgsRequest tgsRequest) {
        return new Event(KrbClientEventType.TKT_INTENT, tgsRequest);
    }

    public static Event createTgtResultEvent(AsRequest asRequest) {
        return new Event(KrbClientEventType.TGT_RESULT, asRequest);
    }

    public static Event createTktResultEvent(TgsRequest tgsRequest) {
        return new Event(KrbClientEventType.TKT_RESULT, tgsRequest);
    }
}
