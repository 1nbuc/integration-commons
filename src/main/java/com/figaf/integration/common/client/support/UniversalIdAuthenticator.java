package com.figaf.integration.common.client.support;

import com.fasterxml.jackson.core.type.TypeReference;
import com.figaf.integration.common.client.support.payload.UniversalIdAuthContext;
import com.figaf.integration.common.entity.RequestContext;
import com.figaf.integration.common.exception.UniversalIdAuthenticationException;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.MultiValueMap;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.HttpCookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class UniversalIdAuthenticator {

    private final RequestContext requestContext;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final UniversalIdAuthContext authContext;

    public UniversalIdAuthenticator(RequestContext requestContext, UniversalIdAuthContext universalIdAuthContext) {

        this.requestContext = requestContext;
        CloseableHttpClient httpClient = HttpClientBuilder.create()
            .disableRedirectHandling()
            .build();
        HttpComponentsClientHttpRequestFactory clientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        this.restTemplate = new RestTemplate(clientHttpRequestFactory);
        this.objectMapper = new ObjectMapper();
        this.authContext = universalIdAuthContext;
    }

    public String authenticateAndGetRedirectLocation() throws UniversalIdAuthenticationException {
        authContext.setHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 FigafInvoker/1.0");

        try {
            // Step 1 is the failing request itself that provides initial values
            step2_prepareLoginAndCookies(authContext);
            step3_runLogin(authContext);
            step4_getAuthCookies(authContext);
            step5_fetchUniversalIdCookie(authContext);
            step6_getAccountInfo(authContext);
            step7_getJwt(authContext);
            step8_selectAccountIfNeeded(authContext);
            step9_getPreAuthToken(authContext);
            step10_loadSdkBootstrap(authContext);
            step11_getCdcAuthToken(authContext);
            step12_getSamlRequestForm(authContext);
            step13_gigyaSsoPost(authContext);
            step14_getSamlResponseFormViaGigyaContinue(authContext);
            step15_loadGigyaJs(authContext);
            step16_finalizeAuthToSapAccountsAcs(authContext);
            step17_samlCallbackToTenantAuth(authContext);
            return step18_followFinalAuthUrl(authContext);

        } catch (UniversalIdAuthenticationException e) {
            log.error("Universal ID Authentication failed: {}", e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during Universal ID Authentication: {}", e.getMessage(), e);
            throw new UniversalIdAuthenticationException("Unexpected error: " + e.getMessage(), e);
        }
    }

    private HttpHeaders buildHeaders(UniversalIdAuthContext authContext, URI targetUri) {
        HttpHeaders headers = new HttpHeaders();
        authContext.getAllHeaders().forEach(headers::set);
        String cookieHeader = authContext.getCookiesForUrl(targetUri);
        if (cookieHeader != null && !cookieHeader.isEmpty()) {
            headers.set("Cookie", cookieHeader);
        }
        return headers;
    }

    private HttpHeaders buildHeaders(UniversalIdAuthContext authContext, URI targetUri, HttpHeaders customHeaders) {
        HttpHeaders headers = buildHeaders(authContext, targetUri); // Gets base headers with cookies
        if (customHeaders != null) {
            headers.addAll(customHeaders);
        }
        return headers;
    }

    private void processResponseCookies(HttpHeaders httpHeaders, UniversalIdAuthContext authContext, String requestDomain) {
        List<String> setCookieHeaders = httpHeaders.get(HttpHeaders.SET_COOKIE);
        if (setCookieHeaders != null) {
            for (String setCookieHeader : setCookieHeaders) {
                authContext.addCookieFromHeader(setCookieHeader, requestDomain);
            }
        }
    }

    private void processResponseCookies(ResponseEntity<?> responseEntity, UniversalIdAuthContext authContext, String requestDomain) {
        processResponseCookies(responseEntity.getHeaders(), authContext, requestDomain);
    }

    private String executeGetAndExtractRedirectLocation(UniversalIdAuthContext context, String currentStepName, String targetUrl, HttpHeaders customHeaders) throws UniversalIdAuthenticationException {
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException(String.format("%s: Invalid target URL: %s", currentStepName, targetUrl), e);
        }

        HttpHeaders headers = buildHeaders(context, uri, customHeaders); // Pass customHeaders to be merged
        // Ensure Accept header if not already set by customHeaders or buildHeaders
        if (headers.getAccept().isEmpty()) {
            headers.setAccept(Collections.singletonList(MediaType.TEXT_HTML));
        }
        // Referer is typically set by the calling step or from context via buildHeaders

        RequestEntity<Void> requestEntity = new RequestEntity<>(headers, HttpMethod.GET, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("{}: Requesting GET {}", currentStepName, targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            if (responseEntity.getStatusCode().is3xxRedirection()) {
                String locationHeader = responseEntity.getHeaders().getFirst(HttpHeaders.LOCATION);
                if (locationHeader == null) {
                    throw new UniversalIdAuthenticationException(String.format("%s: Redirect status %s received but Location header is missing.", currentStepName, responseEntity.getStatusCode()));
                }
                log.debug("{}: Extracted Location header: {}", currentStepName, locationHeader);
                context.setHeader("Referer", targetUrl);
                return locationHeader;
            } else {
                throw new UniversalIdAuthenticationException(String.format("%s: Expected a redirect from %s, but received status %s.", currentStepName, targetUrl, responseEntity.getStatusCode()));
            }
        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException(String.format("%s: Failed request to %s. Status: %s, Body: %s", currentStepName, targetUrl, e.getStatusCode(), e.getResponseBodyAsString()), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException(String.format("%s: Error processing request to %s.", currentStepName, targetUrl), e);
        }
    }

    private void step2_prepareLoginAndCookies(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 2: Prepare Login and Cookies (Follow initial_auth_url)");
        if (context.getInitialAuthUrl() == null)
            throw new UniversalIdAuthenticationException("Step 2: InitialAuthUrl is null.");
        String locationHeader = executeGetAndExtractRedirectLocation(context, "Step 2", context.getInitialAuthUrl(), null);
        context.setLoginUrl(locationHeader);
    }

    private void step3_runLogin(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 3: Run Login (Follow login_url)");
        if (context.getLoginUrl() == null) throw new UniversalIdAuthenticationException("Step 3: LoginUrl is null.");

        String targetUrl = context.getLoginUrl();
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 3: Invalid LoginUrl: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setAccept(Collections.singletonList(MediaType.TEXT_HTML));

        RequestEntity<Void> requestEntity = new RequestEntity<>(buildHeaders(context, uri, customHeaders), HttpMethod.GET, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 3: Requesting {}", targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());
            List<String> setCookieList = responseEntity.getHeaders().get(HttpHeaders.SET_COOKIE.toLowerCase());
            List<HttpCookie> parsedCookies = HttpCookie.parse(setCookieList.get(0));

            HttpCookie csrfValueCookie = parsedCookies.stream()
                .filter(cookie -> cookie.getName().equals("X-Uaa-Csrf"))
                .findFirst()
                .orElseThrow();

            context.setXUaaCsrfToken(csrfValueCookie.getValue());
            String responseBody = responseEntity.getBody();
            if (responseBody == null) {
                throw new UniversalIdAuthenticationException("Step 3: Response body is null.");
            }

            Document doc = Jsoup.parse(responseBody);
            Element metaRedirect = doc.selectFirst("meta[name=redirect]");
            if (metaRedirect != null) {
                String content = metaRedirect.attr("content");
                String authCookieUrl = content.replace("+", "%20"); // Ensure & is replaced
                context.setAuthCookieUrl(authCookieUrl);
                log.debug("Step 3: Extracted authCookieUrl: {}", authCookieUrl);

                URI authCookieUri = new URI(authCookieUrl);
                if (authCookieUri.getQuery() != null) {
                    context.setSamlRelayStateValue(authCookieUri.getQuery());
                    log.debug("Step 3: Extracted relay_state_sap (as samlRelayStateValue): {}", authCookieUri.getQuery());
                }
            } else {
                throw new UniversalIdAuthenticationException("Step 3: Could not find meta redirect tag.");
            }
            context.setHeader("Referer", uri.toString());
        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 3: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 3: Error processing request.", e);
        }
    }

    private void step4_getAuthCookies(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 4: Get Auth Cookies (Follow auth_cookie_url)");
        if (context.getAuthCookieUrl() == null)
            throw new UniversalIdAuthenticationException("Step 4: AuthCookieUrl is null.");

        URI uri;
        try {
            uri = new URI(context.getAuthCookieUrl());
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 4: Invalid AuthCookieUrl: " + context.getAuthCookieUrl(), e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setAccept(Collections.singletonList(MediaType.TEXT_HTML));

        ResponseEntity<String> response;
        try {
            log.debug("Step 4: Requesting {}", uri);
            RequestEntity<Void> req = new RequestEntity<>(buildHeaders(context, uri, customHeaders), HttpMethod.GET, uri);
            response = restTemplate.exchange(req, String.class);
            processResponseCookies(response, context, uri.getHost());

            if (response.getStatusCode().is3xxRedirection()) {
                String locationHeader = response.getHeaders().getFirst(HttpHeaders.LOCATION);
                log.warn("Step 4: Received redirect to {} with status {}. This might be an alternative flow or error.", locationHeader, response.getStatusCode());
                context.setHeader("Referer", uri.toString());

            } else if (!response.getStatusCode().is2xxSuccessful()) {
                throw new UniversalIdAuthenticationException("Step 4: Failed. Status: " + response.getStatusCode() + ", Body: " + response.getBody());
            }

            String xsrfHostCookie = context.getCollectedCookies().stream()
                .filter(c -> "__HOST-XSRF_COOKIE".equalsIgnoreCase(c.getName()) && uri.getHost().equalsIgnoreCase(c.getDomain()))
                .map(HttpCookie::getValue).findFirst().orElse(null);

            if (xsrfHostCookie != null) {
                context.setInitialXsrfHostCookieValue(xsrfHostCookie);
                log.debug("Step 4: Extracted __HOST-XSRF_COOKIE: {}", xsrfHostCookie);
            } else {
                log.warn("Step 4: __HOST-XSRF_COOKIE not found from {}. This might be an issue.", uri.getHost());
            }
            context.setHeader("Referer", uri.toString());

        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 4: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 4: Error processing request.", e);
        }
    }

    private void step5_fetchUniversalIdCookie(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 5: Fetch Universal ID Cookie (POST to /uid-core/authenticate)");
        String targetUrl = "https://core-api.account.sap.com/uid-core/authenticate";
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 5: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setContentType(MediaType.APPLICATION_JSON);
        customHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        customHeaders.set("Origin", "https://account.sap.com");
        // Referer is set by buildHeaders from context

        Map<String, String> bodyMap = new HashMap<>();
        bodyMap.put("login", requestContext.getConnectionProperties().getUsername());
        bodyMap.put("password", requestContext.getConnectionProperties().getPassword());
        String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(bodyMap);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new UniversalIdAuthenticationException("Step 5: Failed to serialize JSON body", e);
        }

        RequestEntity<String> requestEntity = new RequestEntity<>(jsonBody, buildHeaders(context, uri, customHeaders), HttpMethod.POST, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 5: Requesting {} with username {}", targetUrl, requestContext.getConnectionProperties().getUsername());
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            String responseBody = responseEntity.getBody();
            if (responseBody == null) {
                throw new UniversalIdAuthenticationException("Step 5: Response body is null.");
            }

            Map<String, String> responseMap = objectMapper.readValue(responseBody, new TypeReference<>() {
            });
            String cookieName = (String) responseMap.get("cookieName");
            // Value gets transmitted as gac_3_8jfs.... but should be 3_8jfs...
            cookieName = cookieName.substring(4);
            String cookieValue = (String) responseMap.get("cookieValue");

            if (cookieName != null && cookieValue != null) {
                context.setCdcApiKey(cookieName);
                context.setCdcLoginToken(cookieValue);
                log.debug("Step 5: Extracted UID cookieName: {}, cookieValue: (hidden)", cookieName);
            } else {
                throw new UniversalIdAuthenticationException("Step 5: Could not extract cookieName or cookieValue from response. Body: " + responseBody);
            }
            context.setHeader("Referer", targetUrl);

        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 5: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 5: Error processing request.", e);
        }
    }

    private void step6_getAccountInfo(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 6: Get Account Info (POST to accounts.getAccountInfo)");
        if (context.getCdcApiKey() == null || context.getCdcLoginToken() == null) {
            throw new UniversalIdAuthenticationException("Step 6: UID cookieName or cookieValue is missing.");
        }
        String targetUrl = "https://cdc-api.account.sap.com/accounts.getAccountInfo";
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 6: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        customHeaders.setAccept(Collections.singletonList(MediaType.ALL));
        customHeaders.set("Origin", "https://account.sap.com");
        // Referer is set by buildHeaders from context

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("include", "profile,data");
        body.add("lang", "en");
        body.add("APIKey", context.getCdcApiKey());
        body.add("sdk", "js_latest");
        body.add("login_token", context.getCdcLoginToken());
        body.add("authMode", "cookie");
        body.add("sdkBuild", "17508");
        body.add("format", "json");

        RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(body, buildHeaders(context, uri, customHeaders), HttpMethod.POST, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 6: Requesting {}", targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            String responseBody = responseEntity.getBody();
            if (responseBody == null) {
                throw new UniversalIdAuthenticationException("Step 6: Response body is null.");
            }
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            String uid = (String) responseMap.get("UID");
            if (uid != null) {
                context.setAccountId(uid);
                log.debug("Step 6: Extracted AccountId (UID): {}", uid);
            } else {
                throw new UniversalIdAuthenticationException("Step 6: Could not extract UID from response. Body: " + responseBody);
            }
            context.setHeader("Referer", targetUrl);
        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 6: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 6: Error processing request.", e);
        }
    }

    private void step7_getJwt(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 7: Get JWT (POST to accounts.getJWT)");
        if (context.getCdcApiKey() == null || context.getCdcLoginToken() == null) {
            throw new UniversalIdAuthenticationException("Step 7: UID cookieName or cookieValue is missing.");
        }
        String targetUrl = "https://cdc-api.account.sap.com/accounts.getJWT";
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 7: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        customHeaders.setAccept(Collections.singletonList(MediaType.ALL));
        customHeaders.set("Origin", "https://account.sap.com");
        // Referer is set by buildHeaders from context

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("expiration", "180");
        body.add("APIKey", context.getCdcApiKey());
        body.add("sdk", "js_latest");
        body.add("login_token", context.getCdcLoginToken());
        body.add("authMode", "cookie");
        body.add("sdkBuild", "17508");
        body.add("format", "json");

        RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(body, buildHeaders(context, uri, customHeaders), HttpMethod.POST, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 7: Requesting {}", targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            String responseBody = responseEntity.getBody();
            if (responseBody == null) {
                throw new UniversalIdAuthenticationException("Step 7: Response body is null.");
            }
            Map<String, Object> responseMap = (Map<String, Object>) objectMapper.readValue(responseBody, Map.class);
            String idToken = (String) responseMap.get("id_token");
            if (idToken != null) {
                context.setJwtIdToken(idToken);
                log.debug("Step 7: Extracted JWT (id_token)");
            } else {
                throw new UniversalIdAuthenticationException("Step 7: Could not extract id_token from response. Body: " + responseBody);
            }
            context.setHeader("Referer", targetUrl);
        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 7: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 7: Error processing request.", e);
        }
    }

    private void step8_selectAccountIfNeeded(UniversalIdAuthContext context) {
        log.debug("Step 8: Select Account (PUT to /uid-core/accounts/{accID}/selectedAccount) - Conditional");
        if (context.getAccountId() == null || context.getJwtIdToken() == null) {
            log.warn("Step 8: Skipping account selection as AccountId or JWT is missing.");
            return;
        }

        String targetUrl = "https://core-api.account.sap.com/uid-core/accounts/" + context.getAccountId() + "/selectedAccount";
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 9: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setContentType(MediaType.APPLICATION_JSON);
        customHeaders.setBearerAuth(context.getJwtIdToken());

        String jsonPayload = "{\"idsName\":\"" + requestContext.getUniversalAuthAccountId() + "\",\"automatic\":false}";

        RequestEntity<String> requestEntity = new RequestEntity<>(jsonPayload, buildHeaders(context, uri, customHeaders), HttpMethod.PUT, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 8: Requesting {}", targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());
        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 8: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 8: Error processing request.", e);
        }
    }

    private void step9_getPreAuthToken(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 9: Get Pre-Auth Token (GET /uid-core/refreshCDCLoginToken)");
        if (context.getJwtIdToken() == null) {
            throw new UniversalIdAuthenticationException("Step 9: JWT (id_token) is missing.");
        }
        String targetUrl = "https://core-api.account.sap.com/uid-core/refreshCDCLoginToken";
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 9: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        customHeaders.setBearerAuth(context.getJwtIdToken());
        customHeaders.set("Origin", "https://account.sap.com");

        RequestEntity<Void> requestEntity = new RequestEntity<>(buildHeaders(context, uri, customHeaders), HttpMethod.GET, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 9: Requesting {}", targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            String responseBody = responseEntity.getBody();
            if (responseBody == null) {
                throw new UniversalIdAuthenticationException("Step 9: Response body is null.");
            }
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            String cookieName = (String) responseMap.get("cookieName");
            String cookieValue = (String) responseMap.get("cookieValue");

            if (cookieName != null && cookieValue != null) {
                context.setCdcPreAuthCookieName(cookieName);
                context.setCdcPreAuthCookieValue(cookieValue);
                log.debug("Step 9: Extracted CDC PreAuth cookieName: {}, cookieValue: (hidden)", cookieName);
            } else {
                throw new UniversalIdAuthenticationException("Step 9: Could not extract CDC PreAuth cookieName or cookieValue. Body: " + responseBody);
            }
            context.setHeader("Referer", targetUrl);
        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 9: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 9: Error processing request.", e);
        }
    }

    private void step10_loadSdkBootstrap(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 10: Load SDK Bootstrap (GET accounts.webSdkBootstrap)");
        if (context.getCdcApiKey() == null) {
            throw new UniversalIdAuthenticationException("Step 10: UID CookieName (APIKey) is missing.");
        }

        String apiKey = context.getCdcApiKey();
        String simplifiedPageUrl = "https://account.sap.com/core/SAMLProxyPage.html%3FapiKey%3D" + apiKey;

        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl("https://cdc-api.account.sap.com/accounts.webSdkBootstrap")
            .queryParam("apiKey", apiKey)
            .queryParam("pageURL", simplifiedPageUrl)
            .queryParam("sdk", "js_latest")
            .queryParam("sdkBuild", "17508")
            .queryParam("format", "json");

        URI uri;
        try {
            uri = builder.build(true).toUri();
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 10: Failed to build URI for webSdkBootstrap", e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setAccept(Collections.singletonList(MediaType.ALL));
        customHeaders.set("Origin", "https://account.sap.com");

        RequestEntity<Void> requestEntity = new RequestEntity<>(buildHeaders(context, uri, customHeaders), HttpMethod.GET, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 10: Requesting {}", uri);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            boolean gmidFound = context.getCollectedCookies().stream().anyMatch(c -> "gmid".equalsIgnoreCase(c.getName()));
            boolean ucidFound = context.getCollectedCookies().stream().anyMatch(c -> "ucid".equalsIgnoreCase(c.getName()));
            if (!gmidFound || !ucidFound) {
                log.warn("Step 10: gmid or ucid cookie might not have been set. Check response cookies.");
            } else {
                log.debug("Step 10: gmid and ucid cookies processed.");
            }
            context.setHeader("Referer", uri.toString());
        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 10: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 10: Error processing request.", e);
        }
    }

    private void step11_getCdcAuthToken(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 11: Get CDC Auth Token (GET socialize.notifyLogin)");
        if (context.getCdcPreAuthCookieValue() == null || context.getCdcApiKey() == null) {
            throw new UniversalIdAuthenticationException("Step 11: CDC PreAuthCookieValue or UID CookieName (APIKey) is missing.");
        }

        String simplifiedPageUrl = "https://account.sap.com/core/SAMLProxyPage.html%3FapiKey%3D" + context.getCdcApiKey();

        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl("https://cdc-api.account.sap.com/socialize.notifyLogin")
            .queryParam("sessionExpiration", "2419200")
            .queryParam("authCode", context.getCdcPreAuthCookieValue())
            .queryParam("lang", "en")
            .queryParam("APIKey", context.getCdcApiKey())
            .queryParam("sdk", "js_latest")
            .queryParam("authMode", "cookie")
            .queryParam("pageURL", simplifiedPageUrl)
            .queryParam("sdkBuild", "17508")
            .queryParam("format", "json");

        URI uri;
        try {
            uri = builder.build(true).toUri();
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 11: Failed to build URI for socialize.notifyLogin", e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setAccept(Collections.singletonList(MediaType.ALL));
        customHeaders.set("Origin", "https://account.sap.com");

        RequestEntity<Void> requestEntity = new RequestEntity<>(buildHeaders(context, uri, customHeaders), HttpMethod.GET, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 11: Requesting {}", uri);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            String responseBody = responseEntity.getBody();
            if (responseBody == null) {
                throw new UniversalIdAuthenticationException("Step 11: Response body is null.");
            }
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            String loginToken = (String) responseMap.get("login_token");
            if (loginToken != null) {
                context.setCdcNotifyLoginToken(loginToken);
                log.debug("Step 11: Extracted CDC Login Token (login_token)");
            } else {
                throw new UniversalIdAuthenticationException("Step 11: Could not extract login_token from response. Body: " + responseBody);
            }
            context.setHeader("Referer", uri.toString());
        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 11: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 11: Error processing request.", e);
        }
    }

    private void step12_getSamlRequestForm(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 12: Get SAML Request Form (POST to accounts.sap.com/oauth2/authorize)");
        if (context.getJwtIdToken() == null || context.getInitialXsrfHostCookieValue() == null || context.getSamlRelayStateValue() == null) {
            throw new UniversalIdAuthenticationException("Step 12: JWT, InitialXsrfHostCookie, or SamlRelayState (from step 3) is missing.");
        }
        String targetUrl = "https://accounts.sap.com/oauth2/authorize";
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 12: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        customHeaders.setAccept(Collections.singletonList(MediaType.TEXT_HTML));
        customHeaders.set("Referer", "https://accounts.sap.com/");
        customHeaders.set("Origin", "https://accounts.sap.com");

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("utf8", "✓");
        body.add("authenticity_token", context.getJwtIdToken());
        body.add("xsrfProtection", context.getInitialXsrfHostCookieValue());
        body.add("method", "GET");
        body.add("idpSSOEndpoint", "https://accounts.sap.com/oauth2/authorize");
        body.add("sp", "uaa-cf-ap21");
        body.add("RelayState", context.getSamlRelayStateValue());

        if (context.getInitialAuthUrl() == null) {
            throw new UniversalIdAuthenticationException("Step 12: InitialAuthUrl (for form's targetUrl) is missing.");
        }
        body.add("targetUrl", context.getInitialAuthUrl());
        body.add("spName", "uaa-cf-ap21");
        body.add("j_username", requestContext.getConnectionProperties().getUsername());

        RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(body, buildHeaders(context, uri, customHeaders), HttpMethod.POST, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 12: Requesting {}", targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            String responseBody = responseEntity.getBody();
            if (responseBody == null) {
                throw new UniversalIdAuthenticationException("Step 12: Response body is null.");
            }

            Document doc = Jsoup.parse(responseBody);
            Element samlRedirectForm = doc.selectFirst("form#samlRedirect");
            if (samlRedirectForm == null) {
                samlRedirectForm = doc.selectFirst("form");
                if (samlRedirectForm == null) {
                    throw new UniversalIdAuthenticationException("Step 12: Could not find SAML redirect form in response. Body: " + responseBody.substring(0, Math.min(500, responseBody.length())));
                }
            }

            String actionUrl = samlRedirectForm.attr("action");
            context.setSamlActionUrl(actionUrl);
            log.debug("Step 12: Extracted SAML form actionUrl: {}", actionUrl);

            Element samlRequestInput = samlRedirectForm.selectFirst("input[name=SAMLRequest]");
            Element relayStateInput = samlRedirectForm.selectFirst("input[name=RelayState]");
            Element authenticityTokenInput = samlRedirectForm.selectFirst("input[name=authenticity_token]");

            if (samlRequestInput != null) context.setSamlRequestValue(samlRequestInput.attr("value"));
            if (relayStateInput != null) context.setSamlRelayStateValue(relayStateInput.attr("value"));
            if (authenticityTokenInput != null) context.setSamlAuthenticityToken(authenticityTokenInput.attr("value"));

            if (context.getSamlRequestValue() == null) {
                throw new UniversalIdAuthenticationException("Step 12: Could not extract SAMLRequest from form.");
            }
            log.debug("Step 12: SAMLRequest extracted.");
            context.setHeader("Referer", targetUrl);

        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 12: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 12: Error processing request.", e);
        }
    }

    private void step15_loadGigyaJs(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 13: Load Gigya JS (GET gigya.js)");
        if (context.getCdcApiKey() == null) {
            throw new UniversalIdAuthenticationException("Step 13: UID CookieName (APIKey) is missing for Gigya JS URL.");
        }
        String targetUrl = "https://cdc-api.account.sap.com/js/gigya.js?apiKey=" + context.getCdcApiKey();
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 13: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();

        RequestEntity<Void> requestEntity = new RequestEntity<>(buildHeaders(context, uri, customHeaders), HttpMethod.GET, uri);
        ResponseEntity<String> responseEntity;
        try {
            log.debug("Step 13: Requesting {}", targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            String responseBody = responseEntity.getBody();
            if (responseBody == null) {
                throw new UniversalIdAuthenticationException("Step 13: Gigya JS response body is null.");
            }
            Pattern pattern = Pattern.compile("\"ssoKey\":\\s*\"([^\"]+)\"");
            Matcher matcher = pattern.matcher(responseBody);
            if (matcher.find()) {
                context.setSsoKeyFromGigyaJs(matcher.group(1));
                log.debug("Step 13: Extracted ssoKeyFromGigyaJs: {}", context.getSsoKeyFromGigyaJs());
            } else {
                log.warn("Step 13: Could not extract ssoKey from Gigya JS.");
            }

        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 13: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 13: Error processing request.", e);
        }
    }

    private void step13_gigyaSsoPost(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 13: Gigya SSO POST");
        if (context.getSamlActionUrl() == null || !context.getSamlActionUrl().contains("fidm.eu1.gigya.com")) {
            throw new UniversalIdAuthenticationException("Step 13: SamlActionUrl for Gigya is missing or incorrect: " + context.getSamlActionUrl());
        }
        String targetUrl = context.getSamlActionUrl();
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 13: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setContentType(MediaType.MULTIPART_FORM_DATA);
        customHeaders.set("Origin", "https://accounts.sap.com");


        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("utf8", "✓");
        body.add("authenticity_token", context.getSamlAuthenticityToken());
        body.add("SAMLRequest", context.getSamlRequestValue());
        body.add("RelayState", context.getSamlRelayStateValue());
        body.add("login_hint", requestContext.getConnectionProperties().getUsername());

        RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(body, buildHeaders(context, uri, customHeaders), HttpMethod.POST, uri);
        ResponseEntity<String> responseEntity;

        try {
            log.debug("Step 13 (POST): Requesting {}", targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            // Since redirects are off on HttpClient, a 3xx will be returned directly in responseEntity
            processResponseCookies(responseEntity, context, uri.getHost());

            if (responseEntity.getStatusCode().is3xxRedirection()) {
                String locationHeader = responseEntity.getHeaders().getFirst(HttpHeaders.LOCATION);
                if (locationHeader == null) {
                    throw new UniversalIdAuthenticationException("Step 13: Redirect status " + responseEntity.getStatusCode() + " received but Location header is missing.");
                }

                log.debug("Step 13: Extracted Gigya Continue URL: {}", locationHeader);

                try {
                    URI locationUri = new URI(locationHeader);
                    Map<String, String> queryParams = UriComponentsBuilder.fromUri(locationUri).build().getQueryParams().toSingleValueMap();
                    context.setSamlRequestContext(queryParams.get("samlContext"));
                    log.debug("Step 13: Extracted samlContext: {}", context.getSamlRequestContext());
                } catch (Exception parseEx) {
                    throw new UniversalIdAuthenticationException("Step 13: Failed to parse samlContext from Gigya redirect URL: " + locationHeader, parseEx);
                }
                context.setHeader("Referer", targetUrl);
            } else {
                // This is an unexpected outcome if a redirect is always expected.
                throw new UniversalIdAuthenticationException("Step 13: Expected redirect but got status " + responseEntity.getStatusCode() + ". Body: " + responseEntity.getBody());
            }
        } catch (HttpStatusCodeException e) {
            // This would catch 4xx/5xx errors if RestTemplate throws them.
            throw new UniversalIdAuthenticationException("Step 13: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 13: Error processing request.", e);
        }
    }

    private void step14_getSamlResponseFormViaGigyaContinue(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 14: Get SAML Response Form via Gigya Continue");

        String targetUrl = "https://cdc-api.account.sap.com/saml/v2.0/" + context.getCdcApiKey() + "/idp/sso/continue";


        UriComponentsBuilder urlWithParams = UriComponentsBuilder.fromHttpUrl(targetUrl);
        urlWithParams.queryParam("loginToken", context.getCdcLoginToken())
            .queryParam("samlContext", context.getSamlRequestContext());
        URI uri = urlWithParams.build(true).toUri();


        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setAccept(Collections.singletonList(MediaType.TEXT_HTML));
        customHeaders.set("Referer", "https://account.sap.com/");
        customHeaders.set("Cookies", "X-Uaa-Csrf=" + context.getXUaaCsrfToken());


        RequestEntity<Void> requestEntity = new RequestEntity<>(buildHeaders(context, uri, customHeaders), HttpMethod.GET, uri);
        ResponseEntity<String> responseEntity;
        try {
            log.debug("Step 14: Requesting {}", uri);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            String responseBody = responseEntity.getBody();
            if (responseBody == null) {
                throw new UniversalIdAuthenticationException("Step 14: Response body is null.");
            }

            Document doc = Jsoup.parse(responseBody);
            Element samlForm = doc.selectFirst("form");
            if (samlForm == null) {
                throw new UniversalIdAuthenticationException("Step 14: Could not find SAML form in response.");
            }
            String actionUrl = samlForm.attr("action");
            Element samlResponseInput = samlForm.selectFirst("input[name=SAMLResponse]");
            Element relayStateInput = samlForm.selectFirst("input[name=RelayState]");

            if (actionUrl != null) context.setSamlActionUrl(actionUrl);
            if (samlResponseInput != null) context.setSamlResponseValue(samlResponseInput.attr("value"));
            if (relayStateInput != null) context.setSamlRelayStateValue(relayStateInput.attr("value"));

            if (context.getSamlResponseValue() == null) {
                throw new UniversalIdAuthenticationException("Step 14: Could not extract SAMLResponse from form.");
            }
            log.debug("Step 15: SAMLResponse for SAP ACS extracted. Action URL: {}", actionUrl);
            context.setHeader("Referer", uri.toString());

        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException("Step 14: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 14: Error processing request.", e);
        }
    }

    private void step16_finalizeAuthToSapAccountsAcs(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 16: Finalize Auth to SAP Accounts ACS");
        if (context.getSamlActionUrl() == null || !context.getSamlActionUrl().contains("accounts.sap.com/saml2/idp/acs")) {
            throw new UniversalIdAuthenticationException("Step 16: SAML Action URL for SAP ACS is missing or incorrect.");
        }
        if (context.getSamlResponseValue() == null || context.getSamlRelayStateValue() == null) {
            throw new UniversalIdAuthenticationException("Step 16: SAMLResponse or RelayState is missing.");
        }
        String targetUrl = context.getSamlActionUrl();
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 16: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        customHeaders.setAccept(Collections.singletonList(MediaType.TEXT_HTML));
        customHeaders.set("Origin", "https://cdc-api.account.sap.com");
        // Referer is set by buildHeaders from context (should be cdc-api.account.sap.com from step 15)

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("SAMLResponse", context.getSamlResponseValue());
        body.add("RelayState", context.getSamlRelayStateValue());

        RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(body, buildHeaders(context, uri, customHeaders), HttpMethod.POST, uri);

        // Directly handle POST expecting redirect, similar to executePostAndExtractRedirectLocation but specific for this step's needs if any.
        ResponseEntity<String> responseEntity;
        try {
            log.debug("Step 16 (POST): Requesting {}", targetUrl);
            responseEntity = restTemplate.exchange(requestEntity, String.class);
            processResponseCookies(responseEntity, context, uri.getHost());

            if (responseEntity.getStatusCode().is3xxRedirection()) {
                String location = responseEntity.getHeaders().getFirst(HttpHeaders.LOCATION);
                if (location == null) {
                    throw new UniversalIdAuthenticationException(String.format("Step 16: Redirect status %s received but Location header is missing.", responseEntity.getStatusCode()));
                }
                log.debug("Step 16: Extracted Location header: {}", location);
                context.setHeader("Referer", targetUrl);
                context.setFinalCallbackUrl(location);
                log.debug("Step 16: Extracted final callback URL to tenant: {}", location);
            } else {
                throw new UniversalIdAuthenticationException(String.format("Step 16: Expected a redirect from %s, but received status %s.", targetUrl, responseEntity.getStatusCode()));
            }
        } catch (HttpStatusCodeException e) {
            throw new UniversalIdAuthenticationException(String.format("Step 16: Failed request to %s. Status: %s, Body: %s", targetUrl, e.getStatusCode(), e.getResponseBodyAsString()), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException(String.format("Step 16: Error processing request to %s.", targetUrl), e);
        }
    }

    private void step17_samlCallbackToTenantAuth(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 17: SAML Callback to Tenant Auth");
        if (context.getFinalCallbackUrl() == null)
            throw new UniversalIdAuthenticationException("Step 17: FinalCallbackUrl is null.");

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setAccept(Collections.singletonList(MediaType.TEXT_HTML));
        // Referer is set by buildHeaders from context (should be accounts.sap.com from step 16)

        String locationHeader = executeGetAndExtractRedirectLocation(context, "Step 17", context.getFinalCallbackUrl(), customHeaders);
        context.setFinalAuthCodeUrl(locationHeader);
        log.debug("Step 17: Extracted final application URL (with auth code or session): {}", locationHeader);
    }

    private String step18_followFinalAuthUrl(UniversalIdAuthContext context) throws UniversalIdAuthenticationException {
        log.debug("Step 18: Follow Final Auth URL");
        if (context.getFinalAuthCodeUrl() == null)
            throw new UniversalIdAuthenticationException("Step 18: FinalAuthCodeUrl is null.");

        String targetUrl = context.getFinalAuthCodeUrl();
        URI uri;
        try {
            uri = new URI(targetUrl);
        } catch (URISyntaxException e) {
            throw new UniversalIdAuthenticationException("Step 18: Invalid target URL: " + targetUrl, e);
        }

        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.setAccept(Collections.singletonList(MediaType.TEXT_HTML));
        try {
            customHeaders.set("Cookie", context.getCookiesForUrl(new URI(context.getFinalCallbackUrl())));
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        try {
            return executeGetAndExtractRedirectLocation(context, "Step 18", targetUrl, customHeaders);

        } catch (HttpStatusCodeException e) { // Should not be hit for 3xx if RestTemplate is configured correctly
            throw new UniversalIdAuthenticationException("Step 18: Failed. Status: " + e.getStatusCode() + ", Body: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new UniversalIdAuthenticationException("Step 18: Error processing request.", e);
        }
    }

}
