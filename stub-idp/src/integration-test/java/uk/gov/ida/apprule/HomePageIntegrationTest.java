package uk.gov.ida.apprule;

import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.ida.apprule.steps.FormBuilder;
import uk.gov.ida.apprule.steps.PreRegistrationSteps;
import uk.gov.ida.apprule.support.StubIdpAppRule;
import uk.gov.ida.stub.idp.Urls;
import uk.gov.ida.stub.idp.domain.SubmitButtonValue;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;

import static uk.gov.ida.stub.idp.builders.StubIdpBuilder.aStubIdp;

@RunWith(MockitoJUnitRunner.class)
public class HomePageIntegrationTest {

    private static final String IDP_NAME = "stub-idp-demo-one";
    private static final String DISPLAY_NAME = "Stub Idp One Pre-Register";

    @ClassRule
    public static final StubIdpAppRule applicationRule = new StubIdpAppRule()
            .withStubIdp(aStubIdp().withId(IDP_NAME).withDisplayName(DISPLAY_NAME).build());

    public static Client client = JerseyClientBuilder.createClient().property(ClientProperties.FOLLOW_REDIRECTS, false);

    @Before
    public void setUp() {
        client.target("http://localhost:" + applicationRule.getAdminPort() + "/tasks/metadata-refresh").request().post(Entity.text(""));
    }


    @Test
    public void shouldShowLinkToLogInWhenNotLoggedIn() {

        PreRegistrationSteps loggedOutUserVisitsHomePage = new PreRegistrationSteps(client, applicationRule);

        loggedOutUserVisitsHomePage.userSuccessfullyNavigatesTo("")
                .responseContains("Log In");

    }

    @Test
    public void shouldWelcomeUserWhenLoggedIn() {

       PreRegistrationSteps userLogsInAndIsRedirectedToHomePage = new PreRegistrationSteps(client, applicationRule);

        userLogsInAndIsRedirectedToHomePage.userSuccessfullyNavigatesTo("/login")
                .clientPostsFormData(FormBuilder.newForm()
                        .withParam(Urls.IDP_ID_PARAM, IDP_NAME)
                        .withParam(Urls.USERNAME_PARAM, "stub-idp-demo-one")
                        .withParam(Urls.PASSWORD_PARAM,"bar")
                        .withParam(Urls.SUBMIT_PARAM, SubmitButtonValue.SignIn.toString())
                        .build(),
                        "/login")
                .userIsRedirectedTo("")
                .theRedirectIsFollowed()
                .theResponseStatusIs(Response.Status.OK)
                .responseContains("Welcome Jack Bauer", "Logout");

    }
}
