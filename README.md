# kong
Rolling claims builder, which uses short-lived tokens to perform authorization.

Kong uses 3 services to complete Client and User authentication;
## Security (Profile & Client Authentication)
## Manager (User Authentication & Registration)
## Authority (UI Client which delegates calls to Security & Entity Services)

# Typical Application Flow (Web Client)
*   Request Token
*   IF Requires User, Authenticate
*   Introspect / Call Resource

# Request Token
Clients must request a token before calling a resource
1. Verify that Client exists
2. Verify Client secret
3. Validate requested Scopes against the client's allowed scopes
4. When User is required, Validate UserToken
5. Assign consented claims provided by requested Scopes
6. Encrypt Token
