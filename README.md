# Spring Framework MSAL Integration

This project demonstrates integration of Microsoft Authentication Library (MSAL) with Spring Framework for Azure AD authentication, including refresh token functionality.

## Features

- Azure AD authentication using MSAL
- Token refresh support for seamless user experience
- Session management with automatic token refresh
- Role-based access control
- Proper logout with both local and Azure AD session termination

## Technical Components

- Spring Framework 5.3.x
- Spring Security 5.8.x
- Microsoft Authentication Library (MSAL) for Java
- JSP views with JSTL
- Java 8 compatible

## Getting Started

### Prerequisites

- JDK 8 or later
- Maven 3.5+
- Azure AD Application Registration with the following settings:
  - Registered web application in Azure Portal
  - Configured redirect URIs
  - Client ID and Client Secret

### Configuration

1. Update the `application.properties` file with your Azure AD details:

```properties
azure.ad.client-id=your-client-id
azure.ad.client-secret=your-client-secret
azure.ad.tenant-id=your-tenant-id
azure.ad.redirect-uri=http://localhost:9002/spring-msal-demo-1.0.0/login/oauth2/code/
```

2. Build the project:

```bash
mvn clean package
```

3. Deploy the generated WAR file to a servlet container (e.g., Tomcat)

### Usage

1. Access the application at: `http://localhost:9002/spring-msal-demo-1.0.0/`
2. Click "Login with Microsoft" to authenticate
3. After successful authentication, you'll see your user profile and token information

## Token Refresh Flow

This implementation includes automatic token refresh functionality:

1. When a token expires, the application attempts to use the refresh token
2. If successful, the user session continues uninterrupted
3. If unsuccessful, the user is redirected to re-authenticate

## Resources

- [Microsoft Authentication Library (MSAL) for Java](https://github.com/AzureAD/microsoft-authentication-library-for-java)
- [Spring Security Documentation](https://docs.spring.io/spring-security/reference/index.html)
- [Azure Active Directory Documentation](https://docs.microsoft.com/en-us/azure/active-directory/)
