package uk.gov.ida.stub.idp.services;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.X509Credential;

import javax.inject.Inject;
import java.security.cert.X509Certificate;


public class SigningCertFromMetadataExtractorService {

    private final MetadataCredentialResolver credentialResolver;
    private final String entityId;

    @Inject
    public SigningCertFromMetadataExtractorService(MetadataResolver metadataResolver,
                                                   String hubEntityId) throws ComponentInitializationException {
        this.credentialResolver = new MetadataCredentialResolverInitializer(metadataResolver).initialize();
        this.entityId = hubEntityId;
    }

    public X509Certificate getSigningCertFromConnectorMetadata() {
        CriteriaSet criteriaSet = new CriteriaSet(
            new EntityIdCriterion(entityId),
            new UsageCriterion(UsageType.SIGNING),
            new ProtocolCriterion(SAMLConstants.SAML20P_NS),
            new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME)
        );
        try {
            Credential credential = credentialResolver.resolveSingle(criteriaSet);
            if (credential instanceof X509Credential) {
               return ((X509Credential) credential).getEntityCertificate();
            }

        } catch (ResolverException e) {
            throw new RuntimeException(e);
        }
        throw new RuntimeException();
    }
}
