package uk.gov.ida.stub.idp.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;
import uk.gov.ida.saml.metadata.TrustStoreBackedMetadataConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.net.URI;

public class EuropeanIdentityConfiguration {

    @NotNull
    @Valid
    @JsonProperty
    private String hubConnectorEntityId;

    @NotNull
    @Valid
    @JsonProperty
    private boolean enabled;

    @NotNull
    @Valid
    @JsonProperty
    private URI stubCountryMetadataUrl;

    @NotNull
    @Valid
    @JsonProperty
    private TrustStoreBackedMetadataConfiguration metadata;

    public String getHubConnectorEntityId() {
        return hubConnectorEntityId;
    }

    public MetadataResolverConfiguration getMetadata() {
        return metadata;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public URI getStubCountryMetadataUrl() {
        return stubCountryMetadataUrl;
    }
}
