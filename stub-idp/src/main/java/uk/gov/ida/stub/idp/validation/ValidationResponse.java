package uk.gov.ida.stub.idp.validation;

import java.util.ArrayList;
import java.util.List;

public final class ValidationResponse {
    private boolean isOk;
    private List<String> messages;

    public static ValidationResponse aValidResponse() {
        return new ValidationResponse(true, new ArrayList<>());
    }

    public static ValidationResponse anInvalidResponse(List<String> messages) {
        return new ValidationResponse(false, messages);
    }

    private ValidationResponse(boolean ok, List<String> messages) {
        isOk = ok;
        this.messages = messages;
    }

    public boolean isOk() {
        return isOk;
    }

    public boolean isNotOk() {
        return !isOk;
    }

    public List<String> getMessages() {
        return messages;
    }
}
