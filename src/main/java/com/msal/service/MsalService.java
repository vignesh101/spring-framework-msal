package com.msal.service;

import com.microsoft.aad.msal4j.*;
import com.msal.log.DebugLogger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

@Service
@PropertySource("classpath:application.properties")
public class MsalService {

    @Value("${azure.ad.client-id}")
    private String clientId;

    @Value("${azure.ad.client-secret}")
    private String clientSecret;

    @Value("${azure.ad.tenant-id}")
    private String tenantId;

    @Value("${azure.ad.issuer-uri}")
    private String issuerUri;

    @Value("${azure.ad.redirect-uri}")
    private String redirectUri;

    @Value("${azure.ad.graph-api}")
    private String graphApi;

    private static final int STATE_LENGTH = 32;
    private static final int PKCE_LENGTH = 64;

    private static final Set<String> SCOPES = new HashSet<String>() {
        {
            add("User.Read");
            add("profile");
            add("email");
            add("openid");
            add("offline_access");
        }
    };

    private IConfidentialClientApplication clientApp;

    public MsalService(){
        disableCertificateValidation();
    }

    public synchronized IConfidentialClientApplication getClient() throws Exception {
        if (clientApp == null) {
            clientApp = ConfidentialClientApplication.builder(
                            clientId,
                            ClientCredentialFactory.createFromSecret(clientSecret))
                    .authority(issuerUri)
                    .build();
        }
        return clientApp;
    }

    public String getAuthorizationCodeUrl(String state, String nonce) throws Exception {

        Map<String, String> extraQueryParameters = new HashMap<>();
        extraQueryParameters.put("prompt", "select_account login");
        extraQueryParameters.put("access_type", "offline");

        AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters
                .builder(redirectUri, SCOPES)
                .state(state)
                .nonce(nonce)
                .responseMode(ResponseMode.FORM_POST)
                .prompt(Prompt.SELECT_ACCOUNT)
                .build();

        String authUrl = getClient().getAuthorizationRequestUrl(parameters).toString();
        DebugLogger.log("Generated auth URL with custom prompt parameter: " + authUrl);
        return authUrl;
    }

    public IAuthenticationResult acquireToken(String authCode) throws Exception {
        DebugLogger.log("Acquiring token with authorization code");
        AuthorizationCodeParameters parameters = AuthorizationCodeParameters
                .builder(authCode, new java.net.URI(redirectUri))
                .scopes(SCOPES)
                .build();

        CompletableFuture<IAuthenticationResult> future = getClient().acquireToken(parameters);

        try {
            DebugLogger.log("acquire token completed");
            return future.get();
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof MsalException) {
                throw (MsalException) cause;
            } else {
                throw e;
            }
        }
    }


    // Get current account info
    public IAccount getCurrentAccount() throws Exception {
        Set<IAccount> accounts = getClient().getAccounts().join();
        return accounts.isEmpty() ? null : accounts.iterator().next();
    }
    
    /**
     * Acquires a new access token using the refresh token
     * @param refreshToken The refresh token to use
     * @return Authentication result containing access token and refresh token
     * @throws Exception If token acquisition fails
     */
    public IAuthenticationResult acquireTokenByRefreshToken(String refreshToken) throws Exception {
        DebugLogger.log("Attempting to refresh access token using refresh token");
        
        try {
            RefreshTokenParameters parameters = RefreshTokenParameters
                    .builder(SCOPES, refreshToken)
                    .build();
    
            CompletableFuture<IAuthenticationResult> future = getClient().acquireToken(parameters);
            
            return future.get();
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof MsalException) {
                DebugLogger.log("MSAL Exception during token refresh: " + cause.getMessage());
                throw (MsalException) cause;
            } else {
                DebugLogger.log("Unexpected exception during token refresh: " + e.getMessage());
                throw e;
            }
        } catch (Exception e) {
            DebugLogger.log("Exception during token refresh: " + e.getMessage());
            throw e;
        }
    }

    // Generate a random state value for OAuth2 flow
    public static String generateState() {
        return generateSecureString(STATE_LENGTH);
    }

    // Generate a random PKCE value for OAuth2 flow
    public static String generatePkce() {
        return generateSecureString(PKCE_LENGTH);
    }

    // Generate a random secure string
    private static String generateSecureString(int length) {
        byte[] bytes = new byte[length];
        new java.security.SecureRandom().nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // Get user info from Microsoft Graph API
    public String getUserInfo(String accessToken) throws IOException {
        URL url = new URL(graphApi);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("Accept", "application/json");

        // Check for error response code
        int responseCode = conn.getResponseCode();
        if (responseCode >= 400) {
            try (BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(conn.getErrorStream()))) {
                StringBuilder errorResponse = new StringBuilder();
                String line;
                while ((line = errorReader.readLine()) != null) {
                    errorResponse.append(line);
                }
                throw new IOException("Error from Microsoft Graph API: " + responseCode + " - " + errorResponse);
            }
        }

        // Read successful response
        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }

        return response.toString();
    }


    private void disableCertificateValidation() {
        try {
            // Create a trust manager that doesn't validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}