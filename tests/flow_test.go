package tests

/*
	Client Application flow that requires user login to call a resource.
	This is the fullest flow, and the reason kong was built.
	1. Browser hits Client Middleware.
	2. ObtainToken (Will fail, as user or consent is not provided)
	3. Consent (To obtain user's consent on Scopes and their claims)
	4. Login (Displays Login)
	5. AuthenticateUser (Login POST)
	6. Consent (Displays the application's required scopes to user)
	7. AuthorizeConsent (Consent POST)
	8. Send UserToken to Client (Callback)
	9. Goto 1.
*/
