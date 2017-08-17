package uk.gov.ida.saml.idp.test;

import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.algorithm.DigestAlgorithm;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.builders.AuthnStatementBuilder;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;
import uk.gov.ida.saml.core.test.builders.AssertionBuilder;
import uk.gov.ida.saml.idp.test.builders.IPAddressAttributeBuilder;
import uk.gov.ida.saml.idp.test.builders.IssuerBuilder;
import uk.gov.ida.saml.core.test.builders.MatchingDatasetAttributeStatementBuilder_1_1;
import uk.gov.ida.saml.core.test.builders.ResponseBuilder;
import uk.gov.ida.saml.core.test.builders.SignatureBuilder;
import uk.gov.ida.saml.idp.test.builders.SubjectBuilder;
import uk.gov.ida.saml.idp.test.builders.SubjectConfirmationBuilder;
import uk.gov.ida.saml.idp.test.builders.SubjectConfirmationDataBuilder;

import java.util.UUID;
import java.util.function.Function;

import static uk.gov.ida.saml.idp.test.builders.AttributeStatementBuilder.anAttributeStatement;

public class AuthnResponseFactory {

    private final Function<Response, String> responseToStringTransformer;

    public AuthnResponseFactory(Function<Response, String> responseToStringTransformer) {
        this.responseToStringTransformer = responseToStringTransformer;
    }

    public static AuthnResponseFactory anAuthnResponseFactory() {
        return new AuthnResponseFactory(new XmlObjectToBase64EncodedStringTransformer<Response>());
    }

    public Response aResponseFromIdp(
            String idpEntityId,
            String publicCert,
            String privateKey,
            String destination,
            SignatureAlgorithm signatureAlgorithm,
            DigestAlgorithm digestAlgorithm) throws Exception {
        return aResponseFromIdp("a-request", idpEntityId, publicCert, privateKey, destination, signatureAlgorithm, digestAlgorithm);
    }

    public Response aResponseFromIdp(
            String requestId,
            String idpEntityId,
            String destination,
            SignatureAlgorithm signatureAlgorithm,
            DigestAlgorithm digestAlgorithm) throws Exception {
        return aResponseFromIdp(
                requestId,
                idpEntityId,
                TestCertificateStrings.PUBLIC_SIGNING_CERTS.get(idpEntityId),
                TestCertificateStrings.PRIVATE_SIGNING_KEYS.get(idpEntityId),
                destination,
                signatureAlgorithm,
                digestAlgorithm);
    }

    public Response aResponseFromIdp(
            String requestId,
            String idpEntityId,
            String publicCert,
            String privateKey,
            String destination,
            SignatureAlgorithm signatureAlgorithm,
            DigestAlgorithm digestAlgorithm) throws Exception {
        TestCredentialFactory hubEncryptionCredentialFactory =
                new TestCredentialFactory(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT, TestCertificateStrings.HUB_TEST_PRIVATE_ENCRYPTION_KEY);
        TestCredentialFactory idpSigningCredentialFactory =  new TestCredentialFactory(publicCert, privateKey);

        final Subject mdsAssertionSubject = SubjectBuilder.aSubject().withSubjectConfirmation(SubjectConfirmationBuilder.aSubjectConfirmation().withSubjectConfirmationData(SubjectConfirmationDataBuilder.aSubjectConfirmationData().withInResponseTo(requestId).build()).build()).build();
        final Subject authnAssertionSubject = SubjectBuilder.aSubject().withSubjectConfirmation(SubjectConfirmationBuilder.aSubjectConfirmation().withSubjectConfirmationData(SubjectConfirmationDataBuilder.aSubjectConfirmationData().withInResponseTo(requestId).build()).build()).build();
        final AttributeStatement matchingDatasetAttributeStatement = MatchingDatasetAttributeStatementBuilder_1_1.aMatchingDatasetAttributeStatement_1_1().build();
        final Credential encryptingCredential = hubEncryptionCredentialFactory.getEncryptingCredential();
        final Credential signingCredential = idpSigningCredentialFactory.getSigningCredential();
        AttributeStatement ipAddress = anAttributeStatement().addAttribute(IPAddressAttributeBuilder.anIPAddress().build()).build();

        String assertion_id1 = UUID.randomUUID().toString();
        String assertion_id2 = UUID.randomUUID().toString();

        return ResponseBuilder.aResponse()
                .withIssuer(IssuerBuilder.anIssuer().withIssuerId(idpEntityId).build())
                .withSigningCredential(signingCredential)
                .withSignatureAlgorithm(signatureAlgorithm)
                .withDigestAlgorithm(digestAlgorithm)
                .withInResponseTo(requestId)
                .withDestination(destination)
                .addEncryptedAssertion(
                        AssertionBuilder.anAssertion()
                                .withId(assertion_id1)
                                .withIssuer(IssuerBuilder.anIssuer().withIssuerId(idpEntityId).build())
                                .withSubject(mdsAssertionSubject)
                                .addAttributeStatement(matchingDatasetAttributeStatement)
                                .withSignature(SignatureBuilder.aSignature()
                                        .withSigningCredential(signingCredential)
                                        .withSignatureAlgorithm(signatureAlgorithm)
                                        .withDigestAlgorithm(assertion_id1, digestAlgorithm).build())
                                .buildWithEncrypterCredential(encryptingCredential))
                .addEncryptedAssertion(
                        AssertionBuilder.anAssertion()
                                .withId(assertion_id2)
                                .withIssuer(IssuerBuilder.anIssuer().withIssuerId(idpEntityId).build())
                                .withSubject(authnAssertionSubject)
                                .addAttributeStatement(ipAddress)
                                .addAuthnStatement(AuthnStatementBuilder.anAuthnStatement().build())
                                .withSignature(SignatureBuilder.aSignature()
                                        .withSigningCredential(signingCredential)
                                        .withSignatureAlgorithm(signatureAlgorithm)
                                        .withDigestAlgorithm(assertion_id2, digestAlgorithm).build())
                                .buildWithEncrypterCredential(encryptingCredential))
                .build();
    }

    public String aSamlResponseFromIdp(
            String requestId,
            String idpEntityId,
            String destination,
            SignatureAlgorithm signatureAlgorithm,
            DigestAlgorithm digestAlgorithm) throws Exception {
        Response response = aResponseFromIdp(requestId, idpEntityId, destination, signatureAlgorithm, digestAlgorithm);
        return responseToStringTransformer.apply(response);
    }

    public String aSamlResponseFromIdp(
            String requestId,
            String idpEntityId,
            String publicCert,
            String privateKey,
            String destination,
            SignatureAlgorithm signatureAlgorithm,
            DigestAlgorithm digestAlgorithm) throws Exception {
        Response response = aResponseFromIdp(requestId, idpEntityId, publicCert, privateKey, destination, signatureAlgorithm, digestAlgorithm);
        return responseToStringTransformer.apply(response);
    }

    public String aSamlResponseFromIdp(
            String idpEntityId,
            String publicCert,
            String privateKey,
            String destination,
            SignatureAlgorithm signatureAlgorithm,
            DigestAlgorithm digestAlgorithm) throws Exception {
        Response response = aResponseFromIdp("a-request", idpEntityId, publicCert, privateKey, destination, signatureAlgorithm, digestAlgorithm);
        return responseToStringTransformer.apply(response);
    }
}
