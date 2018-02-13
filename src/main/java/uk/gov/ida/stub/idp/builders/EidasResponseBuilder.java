package uk.gov.ida.stub.idp.builders;

import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;

import javax.xml.namespace.QName;
import java.util.List;

public class EidasResponseBuilder {

    private static final String TEMPORARY_PID_TRANSLATION = "UK/EU/";
    private final SecureRandomIdentifierGenerationStrategy idGeneratorStrategy = new SecureRandomIdentifierGenerationStrategy();
    private final String connectorNodeIssuerId;

    public EidasResponseBuilder(String connectorNodeIssuerId) {
        this.connectorNodeIssuerId = connectorNodeIssuerId;
    }

    public Response createEidasResponse(String responseIssuerId, String statusCodeValue, String pid, String loa, List<Attribute> attributes, String inResponseTo, DateTime issueInstant, DateTime assertionIssueInstant, DateTime authnStatementAuthnInstant, String destinationUrl) {
        String responseId = generateRandomId();
        String assertionId = generateRandomId();

        Status status = createStatus(statusCodeValue);

        AuthnStatement authnStatement = createAuthnStatement(loa);
        authnStatement.setAuthnInstant(authnStatementAuthnInstant);

        Subject subject = createSubject(pid);
        AttributeStatement attributeStatement = createAttributeStatement(attributes);
        Issuer responseIssuer = createIssuer(responseIssuerId);
        Issuer assertionIssuer = createIssuer(responseIssuerId);
        Assertion assertion = createAssertion(
                authnStatement,
                subject,
                attributeStatement,
                assertionIssuer,
                assertionId,
                assertionIssueInstant);

        Response response = build(Response.DEFAULT_ELEMENT_NAME);
        response.setStatus(status);
        response.setIssuer(responseIssuer);
        response.getAssertions().add(assertion);
        response.setID(responseId);
        response.setInResponseTo(inResponseTo);
        response.setDestination(destinationUrl);
        response.setIssueInstant(issueInstant);

        return response;
    }

    private String generateRandomId(){
        return idGeneratorStrategy.generateIdentifier(true);
    }

    private Assertion createAssertion(AuthnStatement authnStatement, Subject subject, AttributeStatement attributeStatement, Issuer assertionIssuer, String assertionId, DateTime assertionIssueInstant) {
        Assertion assertion = build(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.getAuthnStatements().add(authnStatement);
        assertion.setSubject(subject);
        assertion.getAttributeStatements().add(attributeStatement);
        assertion.setIssuer(assertionIssuer);
        assertion.setID(assertionId);
        assertion.setIssueInstant(assertionIssueInstant);
        assertion.setConditions(createCondition());
        return assertion;
    }

    private Conditions createCondition() {
        Audience audience = build(Audience.DEFAULT_ELEMENT_NAME);
        audience.setAudienceURI(connectorNodeIssuerId);

        AudienceRestriction audienceRestriction = build(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        audienceRestriction.getAudiences().add(audience);

        Conditions conditions = build(Conditions.DEFAULT_ELEMENT_NAME);
        DateTime now = DateTime.now();
        conditions.setNotBefore(now);
        conditions.setNotOnOrAfter(now.plusMinutes(5));
        conditions.getAudienceRestrictions().add(audienceRestriction);
        return conditions;
    }

    private AttributeStatement createAttributeStatement(List<Attribute> attributes) {
        AttributeStatement attributeStatement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        attributeStatement.getAttributes().addAll(attributes);
        return attributeStatement;
    }

    private AuthnStatement createAuthnStatement(String loa) {
        AuthnStatement authnStatement = build(AuthnStatement.DEFAULT_ELEMENT_NAME);
        AuthnContext authnContext = build(AuthnContext.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef = build(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        authnContextClassRef.setAuthnContextClassRef(loa);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        return authnStatement;
    }

    private Subject createSubject(String pid) {
        Subject subject = build(Subject.DEFAULT_ELEMENT_NAME);
        NameID nameID = build(NameID.DEFAULT_ELEMENT_NAME);
        nameID.setValue(TEMPORARY_PID_TRANSLATION + pid);
        nameID.setFormat(NameIDType.PERSISTENT);
        subject.setNameID(nameID);
        return subject;
    }

    private Status createStatus(String statusCodeValue) {
        Status status = build(Status.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = build(StatusCode.DEFAULT_ELEMENT_NAME);
        statusCode.setValue(statusCodeValue);
        status.setStatusCode(statusCode);
        return status;
    }

    private Issuer createIssuer(String responseIssuerId) {
        Issuer responseIssuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        responseIssuer.setFormat(NameIDType.ENTITY);
        responseIssuer.setValue(responseIssuerId);
        return responseIssuer;
    }
    
    private static <T extends XMLObject> T build(QName elementName) {
        return (T) XMLObjectSupport.buildXMLObject(elementName);
    }
}
