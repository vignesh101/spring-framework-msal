package com.msal.filters;

import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.msal.log.DebugLogger;
import com.msal.model.UserProfile;
import com.msal.service.MsalService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

public class TokenExpirationFilter extends OncePerRequestFilter {

    @Autowired
    private MsalService msalService;

    @Value("${token_time}")
    private boolean useShortenedTokenTime;
    
    @Value("${azure.ad.logout-uri}")
    private String logoutUri;
    
    @Value("${azure.ad.post-logout-redirect-uri}")
    private String postLogoutRedirectUri;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);

        if (session != null) {
            UserProfile userProfile = (UserProfile) session.getAttribute("userInfo");

            if (userProfile != null && userProfile.getTokenExpirationTime() > 0) {
                long tokenExpirationTime = userProfile.getTokenExpirationTime();
                long currentTime = Instant.now().getEpochSecond();

                if (currentTime >= tokenExpirationTime) {
                    DebugLogger.log("Token is expired. Checking for refresh token.");
                    
                    if (userProfile.isRefreshTokenEnabled() && userProfile.getRefreshToken() != null) {
                        try {
                            String refreshToken = userProfile.getRefreshToken();
                            DebugLogger.log("Attempting to refresh token using refresh token");
                            
                            IAuthenticationResult result = msalService.acquireTokenByRefreshToken(refreshToken);
                            
                            if (result != null) {

                                long newExpirationTime = Instant.now().getEpochSecond() + 3600; // Default to 1 hour if not specified
                                userProfile.setTokenExpirationTime(newExpirationTime);
                                userProfile.setTokenExpiresInMinutes(60); // Default to 60 minutes

                                if (useShortenedTokenTime) {
                                    newExpirationTime = Instant.now().getEpochSecond() + 30; // 30 seconds
                                    userProfile.setTokenExpirationTime(newExpirationTime);
                                    userProfile.setTokenExpiresInMinutes(1); // Show as 1 minute in UI
                                }

                                if (result.account() != null && result.account().homeAccountId() != null) {
                                    userProfile.setRefreshToken(result.account().homeAccountId());
                                }
                                
                                DebugLogger.log("Token successfully refreshed. New expiration time: " + newExpirationTime);
                                session.setAttribute("userInfo", userProfile);
                            } else {
                                DebugLogger.log("Token refresh failed - result was null. Redirecting to Azure AD logout.");
                                session.invalidate();

                                try {
                                    String encodedRedirectUri = URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8.toString());
                                    String fullLogoutUrl = logoutUri + "?post_logout_redirect_uri=" + encodedRedirectUri;
                                    
                                    DebugLogger.log("Redirecting to Azure AD logout: " + fullLogoutUrl);
                                    response.sendRedirect(fullLogoutUrl);
                                } catch (Exception e) {
                                    DebugLogger.log("Error creating Azure AD logout URL: " + e.getMessage());
                                    request.getRequestDispatcher("/auth/login?expired=true").forward(request, response);
                                }
                                return;
                            }
                        } catch (Exception e) {
                            DebugLogger.log("Error refreshing token: " + e.getMessage());
                            session.invalidate();

                            try {
                                String encodedRedirectUri = URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8.toString());
                                String fullLogoutUrl = logoutUri + "?post_logout_redirect_uri=" + encodedRedirectUri;
                                
                                DebugLogger.log("Redirecting to Azure AD logout due to token refresh error: " + fullLogoutUrl);
                                response.sendRedirect(fullLogoutUrl);
                            } catch (Exception ex) {
                                DebugLogger.log("Error creating Azure AD logout URL: " + ex.getMessage());
                                request.getRequestDispatcher("/auth/login?expired=true").forward(request, response);
                            }
                            return;
                        }
                    } else {
                        DebugLogger.log("No refresh token available. Invalidating session and redirecting to Azure AD logout.");
                        session.invalidate();

                        try {
                            String encodedRedirectUri = URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8.toString());
                            String fullLogoutUrl = logoutUri + "?post_logout_redirect_uri=" + encodedRedirectUri;
                            
                            DebugLogger.log("Redirecting to Azure AD logout: " + fullLogoutUrl);
                            response.sendRedirect(fullLogoutUrl);
                        } catch (Exception e) {
                            DebugLogger.log("Error creating Azure AD logout URL: " + e.getMessage());
                            request.getRequestDispatcher("/auth/login?expired=true").forward(request, response);
                        }
                        return;
                    }
                }

                long remainingSeconds = tokenExpirationTime - currentTime;
                userProfile.setTokenExpiresInMinutes((int)Math.ceil(remainingSeconds / 60.0));
            }
        }

        filterChain.doFilter(request, response);
    }
}