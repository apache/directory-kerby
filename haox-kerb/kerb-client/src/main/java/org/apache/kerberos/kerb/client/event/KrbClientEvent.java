package org.apache.kerberos.kerb.client.event;

import org.apache.haox.event.Event;
import org.apache.kerberos.kerb.client.request.AsRequest;
import org.apache.kerberos.kerb.client.request.TgsRequest;

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
