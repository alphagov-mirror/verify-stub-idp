package uk.gov.ida.stub.idp;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.stub.idp.configuration.SigningKeyPairConfiguration;
import uk.gov.ida.stub.idp.configuration.StubIdpConfiguration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class StubIdpModuleTest {

    @Mock
    StubIdpConfiguration configuration;

    @Mock
    SigningKeyPairConfiguration signingKeyPairConfiguration;

    @Test
    public void shouldGetKeyStoreWithDeprecatedConfiguration() {
        StubIdpModule module = new StubIdpModule( null);
        when(configuration.getSigningKeyPairConfiguration()).thenReturn(signingKeyPairConfiguration);
        when(signingKeyPairConfiguration.getCert()).thenReturn(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT);
        assertThat(module.getKeyStore(configuration)).isNotNull();
    }

    @Test
    public void shouldGetKeyStoreConfiguration() {
        StubIdpModule module = new StubIdpModule( null);
        when(configuration.getSigningKeyPairConfiguration()).thenReturn(signingKeyPairConfiguration);
        when(signingKeyPairConfiguration.getCert()).thenReturn(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT);
        assertThat(module.getKeyStore(configuration)).isNotNull();
    }

}
