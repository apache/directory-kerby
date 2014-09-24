package org.haox.asn1.type;

public class Asn1Choice extends Asn1Any {
    private Asn1Type[] choices;

    public Asn1Choice(Asn1Type ... choices) {
        super(anyValue(choices));
        this.choices = choices;
    }

    public Asn1Type anyChoiceOf(Class<? extends Asn1Type> type) {
        Asn1Type anyValue = anyValue(this.choices);
        if (anyValue != null && type.isInstance(anyValue)) {
            return anyValue;
        }
        return null;
    }

    public static Asn1Type anyValue(Asn1Type ... choices) {
        for (Asn1Type value : choices) {
            if (value != null) return value;
        }
        return null;
    }
}
