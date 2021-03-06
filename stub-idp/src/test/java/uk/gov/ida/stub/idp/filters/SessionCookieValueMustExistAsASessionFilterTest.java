package uk.gov.ida.stub.idp.filters;

import com.google.common.collect.ImmutableMap;
import com.squarespace.jersey2.guice.JerseyGuiceUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.ida.common.SessionId;
import uk.gov.ida.stub.idp.cookies.HmacValidator;
import uk.gov.ida.stub.idp.exceptions.InvalidSecureCookieException;
import uk.gov.ida.stub.idp.exceptions.SecureCookieNotFoundException;
import uk.gov.ida.stub.idp.exceptions.SessionIdCookieNotFoundException;
import uk.gov.ida.stub.idp.exceptions.SessionNotFoundException;
import uk.gov.ida.stub.idp.repositories.IdpSession;
import uk.gov.ida.stub.idp.repositories.SessionRepository;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.NewCookie;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;
import static uk.gov.ida.stub.idp.cookies.CookieNames.SECURE_COOKIE_NAME;
import static uk.gov.ida.stub.idp.cookies.CookieNames.SESSION_COOKIE_NAME;
import static uk.gov.ida.stub.idp.filters.SessionCookieValueMustExistAsASessionFilter.NO_CURRENT_SESSION_COOKIE_VALUE;

@RunWith(MockitoJUnitRunner.class)
public class SessionCookieValueMustExistAsASessionFilterTest {

    private boolean isSecureCookieEnabled = true;
    @Mock
    private HmacValidator hmacValidator;
    @Mock
    private SessionRepository<IdpSession> idpSessionRepository;
    @Mock
    private ContainerRequestContext containerRequestContext;

    @BeforeClass
    public static void doALittleHackToMakeGuicierHappyForSomeReason() {
        JerseyGuiceUtils.reset();
    }

    @Test(expected = SessionIdCookieNotFoundException.class)
    public void shouldReturnNullWhenCheckingNotRequiredButNoCookies() {
        Map<String, Cookie> cookies = ImmutableMap.of();
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
    }

    @Test(expected = SecureCookieNotFoundException.class)
    public void shouldReturnNullWhenCheckingNotRequiredButSecureCookie() {
        Map<String, Cookie> cookies = ImmutableMap.of(SESSION_COOKIE_NAME, new NewCookie(SESSION_COOKIE_NAME, "some-session-id"));
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
    }

    @Test(expected = InvalidSecureCookieException.class)
    public void shouldReturnNullWhenCheckingNotRequiredButSessionCookieIsSetToNoCurrentValue() {
        Map<String, Cookie> cookies = ImmutableMap.of(SESSION_COOKIE_NAME, new NewCookie(SESSION_COOKIE_NAME, "some-session-id"), SECURE_COOKIE_NAME, new NewCookie(SECURE_COOKIE_NAME, NO_CURRENT_SESSION_COOKIE_VALUE));
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
    }

    @Test(expected = InvalidSecureCookieException.class)
    public void shouldReturnNullWhenCheckingNotRequiredButSessionCookieAndSecureCookieDontMatchUp() {
        SessionId sessionId = SessionId.createNewSessionId();
        Map<String, Cookie> cookies = ImmutableMap.of(SESSION_COOKIE_NAME, new NewCookie(SESSION_COOKIE_NAME, sessionId.toString()), SECURE_COOKIE_NAME, new NewCookie(SECURE_COOKIE_NAME, "secure-cookie"));
        when(hmacValidator.validateHMACSHA256("secure-cookie", sessionId.getSessionId())).thenReturn(false);
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
    }

    @Test
    public void shouldReturnSessionIdWhenCheckingNotRequiredButSessionCookieAndSecureCookieMatchUp() {
        SessionId sessionId = SessionId.createNewSessionId();
        Map<String, Cookie> cookies = ImmutableMap.of(SESSION_COOKIE_NAME, new NewCookie(SESSION_COOKIE_NAME, sessionId.toString()), SECURE_COOKIE_NAME, new NewCookie(SECURE_COOKIE_NAME, "secure-cookie"));
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        when(hmacValidator.validateHMACSHA256("secure-cookie", sessionId.getSessionId())).thenReturn(true);
        when(idpSessionRepository.containsSession(sessionId)).thenReturn(true);
        new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
    }

    @Test
    public void shouldThrowCookieNotFoundExceptionWhenCheckingRequiredButNoCookies() {
        Map<String, Cookie> cookies = ImmutableMap.of();
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        try {
            new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
            fail("we wanted an exception but we got none");
        } catch (SessionIdCookieNotFoundException e) {
            assertThat(e.getMessage()).isEqualTo("Unable to locate session from session cookie");
        }
    }

    @Test
    public void shouldThrowSecureCookieNotFoundExceptionWhenCheckingRequiredButNoSessionIdCookie() {
        Map<String, Cookie> cookies = ImmutableMap.of();
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        try {
            new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
            fail("we wanted an exception but we got none");
        } catch (SessionIdCookieNotFoundException e) {
            assertThat(e.getMessage()).isEqualTo("Unable to locate session from session cookie");
        }
    }

    @Test
    public void shouldThrowSecureCookieNotFoundExceptionWhenCheckingRequiredButNoSecureCookie() {
        Map<String, Cookie> cookies = ImmutableMap.of(
                SESSION_COOKIE_NAME, new NewCookie(SESSION_COOKIE_NAME, "some-session-id")
        );
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        try {
            new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
            fail("we wanted an exception but we got none");
        } catch (SecureCookieNotFoundException e) {
            assertThat(e.getMessage()).isEqualTo("Secure cookie not found.");
        }
    }

    @Test
    public void shouldThrowInvalidSecureExceptionWhenCheckingRequiredButSessionCookieIsSetToNoCurrentValue() {
        Map<String, Cookie> cookies = ImmutableMap.of(
                SESSION_COOKIE_NAME, new NewCookie(SESSION_COOKIE_NAME, "session-id"),
                SECURE_COOKIE_NAME, new NewCookie(SECURE_COOKIE_NAME, NO_CURRENT_SESSION_COOKIE_VALUE)
        );
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        try {
            new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
            fail("we wanted an exception but we got none");
        } catch (InvalidSecureCookieException e) {
            assertThat(e.getMessage()).isEqualTo("Secure cookie was set to deleted session value, indicating a previously completed session.");
        }
    }

    @Test
    public void shoulThrowInvalidSecureCookieExceptionWhenCheckingRequiredButSessionCookieAndSecureCookieDontMatchUp() {
        SessionId sessionId = SessionId.createNewSessionId();
        Map<String, Cookie> cookies = ImmutableMap.of(
                SESSION_COOKIE_NAME, new NewCookie(SESSION_COOKIE_NAME, sessionId.toString()),
                SECURE_COOKIE_NAME, new NewCookie(SECURE_COOKIE_NAME, "secure-cookie")
        );
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        when(hmacValidator.validateHMACSHA256("secure-cookie", sessionId.getSessionId())).thenReturn(false);
        try {
            new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
            fail("we wanted an exception but we got none");
        } catch (InvalidSecureCookieException e) {
            assertThat(e.getMessage()).isEqualTo("Secure cookie value not valid.");
        }
    }

    @Test(expected = SessionNotFoundException.class)
    public void shouldThrowNotFoundIfSessionNotActive() {
        SessionId sessionId = SessionId.createNewSessionId();
        Map<String, Cookie> cookies = ImmutableMap.of(
                SESSION_COOKIE_NAME, new NewCookie(SESSION_COOKIE_NAME, sessionId.toString()),
                SECURE_COOKIE_NAME, new NewCookie(SECURE_COOKIE_NAME, "secure-cookie")
        );
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        when(hmacValidator.validateHMACSHA256("secure-cookie", sessionId.getSessionId())).thenReturn(true);
        new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, isSecureCookieEnabled).filter(containerRequestContext);
    }

    @Test
    public void shouldIgnoreSecureCookieIfSecureCookiesNotEnabled() {
        SessionId sessionId = SessionId.createNewSessionId();
        Map<String, Cookie> cookies = ImmutableMap.of(
                SESSION_COOKIE_NAME, new NewCookie(SESSION_COOKIE_NAME, sessionId.toString()),
                SECURE_COOKIE_NAME, new NewCookie(SECURE_COOKIE_NAME, "secure-cookies")
        );
        when(containerRequestContext.getCookies()).thenReturn(cookies);
        when(idpSessionRepository.containsSession(sessionId)).thenReturn(true);
        new SessionCookieValueMustExistAsASessionFilter(idpSessionRepository, hmacValidator, false).filter(containerRequestContext);
    }
}
