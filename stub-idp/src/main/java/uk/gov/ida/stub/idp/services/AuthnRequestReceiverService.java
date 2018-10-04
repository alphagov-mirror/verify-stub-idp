package uk.gov.ida.stub.idp.services;

import org.apache.commons.lang.StringEscapeUtils;
import org.cryptacular.EncodingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.common.SessionId;
import uk.gov.ida.saml.hub.domain.IdaAuthnRequestFromHub;
import uk.gov.ida.stub.idp.Urls;
import uk.gov.ida.stub.idp.domain.EidasAuthnRequest;
import uk.gov.ida.stub.idp.domain.IdpHint;
import uk.gov.ida.stub.idp.domain.IdpLanguageHint;
import uk.gov.ida.stub.idp.exceptions.InvalidEidasAuthnRequestException;
import uk.gov.ida.stub.idp.repositories.EidasSession;
import uk.gov.ida.stub.idp.repositories.EidasSessionRepository;
import uk.gov.ida.stub.idp.repositories.IdpSession;
import uk.gov.ida.stub.idp.repositories.IdpSessionRepository;

import javax.inject.Inject;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

public class AuthnRequestReceiverService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthnRequestReceiverService.class);

    private final Function<String, IdaAuthnRequestFromHub> samlRequestTransformer;
    private final IdpSessionRepository idpSessionRepository;
    private final EidasSessionRepository eidasSessionRepository;
    private final Function<String, AuthnRequest> stringAuthnRequestTransformer;
    private final Optional<SigningCertFromMetadataExtractorService> signingCertFromMetadataExtractorService;

    public static class SessionCreated {
        private URI nextLocation;
        private SessionId idpSessionId;

        public SessionCreated(URI nextLocation, SessionId idpSessionId) {
            this.nextLocation = nextLocation;
            this.idpSessionId = idpSessionId;
        }

        public SessionId getIdpSessionId() {
            return idpSessionId;
        }

        public URI getNextLocation() {
            return nextLocation;
        }
    }

    @Inject
    public AuthnRequestReceiverService(
            Function<String, IdaAuthnRequestFromHub> samlRequestTransformer,
            IdpSessionRepository idpSessionRepository,
            EidasSessionRepository eidasSessionRepository,
            Function<String, AuthnRequest> stringToAuthnRequestTransformer,
            Optional<SigningCertFromMetadataExtractorService> signingCertFromMetadataExtractorService
    ) {

        this.samlRequestTransformer = samlRequestTransformer;
        this.idpSessionRepository = idpSessionRepository;
        this.eidasSessionRepository = eidasSessionRepository;
        this.stringAuthnRequestTransformer = stringToAuthnRequestTransformer;
        this.signingCertFromMetadataExtractorService = signingCertFromMetadataExtractorService;
    }

    public SessionCreated handleAuthnRequest(String idpName, String samlRequest, Set<String> idpHints,
                                             Optional<Boolean> registration, String relayState,
                                             Optional<IdpLanguageHint> languageHint, Optional<UUID> singleIdpJourneyId) {
        final List<IdpHint> validHints = new ArrayList<>();
        final List<String> invalidHints = new ArrayList<>();
        validateHints(idpHints, validHints, invalidHints);

        final IdaAuthnRequestFromHub idaRequestFromHub = samlRequestTransformer.apply(samlRequest);
        IdpSession session = new IdpSession(SessionId.createNewSessionId(), idaRequestFromHub, relayState, validHints, invalidHints, languageHint, registration, singleIdpJourneyId);
        final SessionId idpSessionId = idpSessionRepository.createSession(session);

        UriBuilder uriBuilder;
        if (registration.isPresent() && registration.get()) {
            uriBuilder = UriBuilder.fromPath(Urls.REGISTER_RESOURCE);
        } else {
            uriBuilder = UriBuilder.fromPath(Urls.LOGIN_RESOURCE);
        }

        return new SessionCreated(uriBuilder.build(idpName), idpSessionId);
    }

    public SessionCreated handleEidasAuthnRequest(String schemeId, String samlRequest, String relayState, Optional<IdpLanguageHint> languageHint) {
        AuthnRequest authnRequest = stringAuthnRequestTransformer.apply(samlRequest);
        validateEidasAuthnRequest(authnRequest);
        EidasAuthnRequest eidasAuthnRequest = EidasAuthnRequest.buildFromAuthnRequest(authnRequest);
        EidasSession session = new EidasSession(SessionId.createNewSessionId(), eidasAuthnRequest, relayState, Collections.emptyList(), Collections.emptyList(), languageHint, Optional.empty());
        final SessionId idpSessionId = eidasSessionRepository.createSession(session);

        UriBuilder uriBuilder = UriBuilder.fromPath(Urls.EIDAS_LOGIN_RESOURCE);

        return new SessionCreated(uriBuilder.build(schemeId), idpSessionId);
    }

    private void validateEidasAuthnRequest(AuthnRequest request) {
        if (request.getSignature().getKeyInfo() == null) {
            throw new InvalidEidasAuthnRequestException("KeyInfo cannot be null");
        }
        if (request.getSignature().getKeyInfo().getX509Datas().isEmpty()) {
            throw new InvalidEidasAuthnRequestException("Must contain X509 data");
        }
        if (request.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().isEmpty()) {
            throw new InvalidEidasAuthnRequestException("Must contain X509 certificate");
        }
        validateEidasAuthRequestSigningCert(request);
    }

    private void validateEidasAuthRequestSigningCert(AuthnRequest request) {
        java.security.cert.X509Certificate connectorX509Cert = signingCertFromMetadataExtractorService.get().getSigningCertFromConnectorMetadata();
        X509Certificate x509RequestSigningCert = request.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
        X509Certificate x509ConnectorSigningCert;
        try {
            x509ConnectorSigningCert = KeyInfoSupport.buildX509Certificate(connectorX509Cert);
        } catch (CertificateEncodingException e) {
            throw new EncodingException("Unable to build OpenSaml X509Cert from Java X509Cert", e);
        }

        if (!x509RequestSigningCert.getValue().equals(x509ConnectorSigningCert.getValue())) {
            throw new InvalidEidasAuthnRequestException("Signing Cert in EidasAuthnRequest does not match X509 in Connector Metadata");
        }
    }

    private void validateHints(Set<String> idpHints, List<IdpHint> validHints, List<String> invalidHints) {
        if (idpHints != null && !idpHints.isEmpty()) {
            for (String hint : idpHints) {
                try {
                    validHints.add(IdpHint.valueOf(hint));
                } catch (IllegalArgumentException e) {
                    // this is a hint that stub-idp does not know about, and it should be able
                    // to deal with such hints.  Also sanitize string
                    invalidHints.add(StringEscapeUtils.escapeHtml(hint));
                }
            }
            if (!validHints.isEmpty()) {
                LOG.info("Received known hints: {}", validHints);
            }
            if (!invalidHints.isEmpty()) {
                LOG.info("Received unknown hints: {}", invalidHints);
            }
        }
    }
}
