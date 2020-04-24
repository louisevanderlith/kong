# kong
Rolling claims builder

# Profile - Is the main configuration for a domain
# Clients - are applications that use resources
# Resources - are information scopes
# Claims - are fields requested by scopes

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
