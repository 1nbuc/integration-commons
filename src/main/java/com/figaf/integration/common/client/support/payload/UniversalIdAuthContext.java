package com.figaf.integration.common.client.support.payload;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apache.hc.client5.http.cookie.Cookie;
import org.apache.hc.core5.http.Header;

import java.net.HttpCookie;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Getter
@Setter
@ToString
public class UniversalIdAuthContext {

    // URLs and Redirects
    private String initialAuthUrl;
    private String loginUrl;
    private String authCookieUrl;
    private String samlActionUrl; // Action URL from SAML redirect forms
    private String gigyaSsoContinueUrl;
    private String finalCallbackUrl; // Callback to tenant after ACS
    private String finalAuthCodeUrl; // URL with auth code for tenant

    // Tokens and Identifiers
    private String clientId;
    private String initialXsrfHostCookieValue; // Value of __HOST-XSRF_COOKIE from accounts.sap.com
    private String xUaaCsrfToken; // X-Uaa-Csrf token from tenant login page
    private String cdcApiKey; // e.g., "glt_3_..."
    private String cdcLoginToken; // Login token from /uid-core/authenticate
    private String accountId; // UID from accounts.getAccountInfo
    private String jwtIdToken; // id_token from accounts.getJWT
    private String cdcPreAuthCookieName; // Name of the pre-auth cookie (e.g. "glt_3_...") from refreshCDCLoginToken
    private String cdcPreAuthCookieValue; // Value of the pre-auth cookie from refreshCDCLoginToken
    private String cdcNotifyLoginToken; // login_token from socialize.notifyLogin
    private String ssoKeyFromGigyaJs;
    private String samlRequestContext; // samlContext query param from Gigya redirect
    private String samlRequestValue; // SAMLRequest form value
    private String samlAuthenticityToken; // authenticity_token for SAML form
    private String samlRelayStateValue; // RelayState form value
    private String samlResponseValue; // SAMLResponse form value
    private List<String> step19SetCookieHeaders; // Specifically store Set-Cookie headers from step 19
    private String signatureCookie;
    private String spName;

    // Collected Cookies (using java.net.HttpCookie for better standard compliance)
    private final List<HttpCookie> collectedCookies = new ArrayList<>();

    // General Headers (e.g., User-Agent, Referer)
    private final Map<String, String> currentHeaders = new HashMap<>();

    public UniversalIdAuthContext() {
        // Initialize with default headers if any
        currentHeaders.put("User-Agent", "Mozilla/5.0 (Java Figaf Integration Commons)");
    }

    public void addCookies(List<HttpCookie> cookies) {
        if (cookies == null) {
            return;
        }
        for (HttpCookie newCookie : cookies) {
            // Remove old cookie with the same name and domain/path if it exists
            collectedCookies.removeIf(existingCookie ->
                existingCookie.getName().equalsIgnoreCase(newCookie.getName()) &&
                (existingCookie.getDomain() == null ? newCookie.getDomain() == null : existingCookie.getDomain().equalsIgnoreCase(newCookie.getDomain())) &&
                (existingCookie.getPath() == null ? newCookie.getPath() == null : existingCookie.getPath().equals(newCookie.getPath()))
            );
            // Add the new cookie
            if (!newCookie.hasExpired()) {
                collectedCookies.add(newCookie);
            }
        }
    }

    public void addCookieFromHeader(String setCookieHeader, String requestDomain) {
        if (setCookieHeader == null || setCookieHeader.isEmpty()) {
            return;
        }
        try {
            List<HttpCookie> parsedCookies = HttpCookie.parse(setCookieHeader);
            for (HttpCookie cookie : parsedCookies) {
                if (cookie.getDomain() == null) {
                    // If domain is not set by the server, it defaults to the request domain
                    cookie.setDomain(requestDomain);
                }
                // Ensure path is not null, default to "/"
                if (cookie.getPath() == null || cookie.getPath().isEmpty()) {
                    cookie.setPath("/");
                }
                addCookies(List.of(cookie));
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Warning: Could not parse Set-Cookie header: " + setCookieHeader + " - " + e.getMessage());
        }
    }


    public String getCookiesForUrl(URI targetUri) {
        if (targetUri == null) {
            return "";
        }
        String targetHost = targetUri.getHost();
        String targetPath = targetUri.getPath() == null ? "/" : targetUri.getPath();

        return collectedCookies.stream()
            .filter(cookie -> {
                if (cookie.hasExpired()) return false;
                String cookieDomain = cookie.getDomain();
                if (cookieDomain == null) return false; // Should not happen if addCookieFromHeader sets it

                // Domain matching logic (simplified, for exact or leading dot)
                boolean domainMatches = targetHost.equalsIgnoreCase(cookieDomain) ||
                                        (cookieDomain.startsWith(".") && targetHost.toLowerCase().endsWith(cookieDomain.toLowerCase()));
                if (!domainMatches) return false;

                // Path matching logic
                String cookiePath = cookie.getPath() == null ? "/" : cookie.getPath();
                boolean pathMatches = targetPath.startsWith(cookiePath);
                return pathMatches;
            })
            .map(cookie -> cookie.getName() + "=" + cookie.getValue())
            .collect(Collectors.joining("; "));
    }

    public void setHeader(String name, String value) {
        this.currentHeaders.put(name, value);
    }

    public String getHeader(String name) {
        return this.currentHeaders.get(name);
    }

    public Map<String, String> getAllHeaders() {
        return new HashMap<>(this.currentHeaders);
    }
}
