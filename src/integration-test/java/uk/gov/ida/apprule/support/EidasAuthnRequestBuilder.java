package uk.gov.ida.apprule.support;

import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;
import org.joda.time.DateTime;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import se.litsec.eidas.opensaml.common.EidasConstants;
import se.litsec.eidas.opensaml.ext.RequestedAttribute;
import se.litsec.eidas.opensaml.ext.RequestedAttributes;
import se.litsec.eidas.opensaml.ext.SPType;
import se.litsec.eidas.opensaml.ext.SPTypeEnumeration;
import se.litsec.eidas.opensaml.ext.attributes.AttributeConstants;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

public class EidasAuthnRequestBuilder {
    private String issuerEntityId = "issuerEntityId";
    private String destination = "destination";
    private DateTime issueInstant = DateTime.now();

    public static EidasAuthnRequestBuilder anAuthnRequest() {
        return new EidasAuthnRequestBuilder();
    }

    public EidasAuthnRequestBuilder withIssuerEntityId(String issuerEntityId) {
        this.issuerEntityId = issuerEntityId;
        return this;
    }

    public EidasAuthnRequestBuilder withDestination(String destination) {
        this.destination = destination;
        return this;
    }

    public EidasAuthnRequestBuilder withIssueInstant(DateTime issueInstant) {
        this.issueInstant = issueInstant;
        return this;
    }

    public String build() {
        AuthnRequest authnRequest = (AuthnRequest) XMLObjectSupport.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setID(new SecureRandomIdentifierGenerationStrategy().generateIdentifier());
        authnRequest.setDestination(destination);
        authnRequest.setIssueInstant(issueInstant);
        authnRequest.setIssuer(createIssuer(issuerEntityId));
        authnRequest.setExtensions(createEidasExtensions());
        authnRequest.setNameIDPolicy(createNameIDPolicy());
        authnRequest.setRequestedAuthnContext(createRequestedAuthnContext(
                AuthnContextComparisonTypeEnumeration.MINIMUM,
                EidasConstants.EIDAS_LOA_SUBSTANTIAL));

        return new XmlObjectToBase64EncodedStringTransformer<>().apply(authnRequest);
    }

    private RequestedAuthnContext createRequestedAuthnContext(AuthnContextComparisonTypeEnumeration comparisonType, String loa) {
        RequestedAuthnContext requestedAuthnContext = (RequestedAuthnContext) XMLObjectSupport.buildXMLObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        requestedAuthnContext.setComparison(comparisonType);

        AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef) XMLObjectSupport.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        authnContextClassRef.setAuthnContextClassRef(loa);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
        return requestedAuthnContext;
    }

    private NameIDPolicy createNameIDPolicy() {
        NameIDPolicy nameIDPolicy = (NameIDPolicy) XMLObjectSupport.buildXMLObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.PERSISTENT);
        return nameIDPolicy;
    }

    private Extensions createEidasExtensions() {
        SPType spType = (SPType) XMLObjectSupport.buildXMLObject(SPType.DEFAULT_ELEMENT_NAME);
        spType.setType(SPTypeEnumeration.PUBLIC);

        RequestedAttributes requestedAttributes = (RequestedAttributes) XMLObjectSupport.buildXMLObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);
        requestedAttributes.getRequestedAttributes().add(createRequestedAttribute(AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_NAME));
        requestedAttributes.getRequestedAttributes().add(createRequestedAttribute(AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_NAME));
        requestedAttributes.getRequestedAttributes().add(createRequestedAttribute(AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_NAME));
        requestedAttributes.getRequestedAttributes().add(createRequestedAttribute(AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_NAME));

        Extensions extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
        extensions.getUnknownXMLObjects().add(spType);
        extensions.getUnknownXMLObjects().add(requestedAttributes);
        return extensions;
    }

    private Issuer createIssuer(String issuerEntityId) {
        Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setFormat(NameIDType.ENTITY);
        issuer.setValue(issuerEntityId);
        return issuer;
    }

    private RequestedAttribute createRequestedAttribute(String requestedAttributeName) {
        RequestedAttribute attr = (RequestedAttribute) XMLObjectSupport.buildXMLObject(RequestedAttribute.DEFAULT_ELEMENT_NAME);
        attr.setName(requestedAttributeName);
        attr.setNameFormat(Attribute.URI_REFERENCE);
        attr.setIsRequired(true);
        return attr;
    }
}