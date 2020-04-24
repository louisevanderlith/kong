package kong

import "kong/scopes"

func InspectRequest(token AccessToken, reqScope scopes.Resource) (map[string]string, error){
	result := make(map[string]string)

	for _, scp := range token.Scopes {
		if scp == reqScope.Name	{

			for _, c := range reqScope.Claims {
				cVal, ok := token.Claims[c]

				if ok {
					result[c] = cVal
				}
			}
		}
	}

	return result, nil
}