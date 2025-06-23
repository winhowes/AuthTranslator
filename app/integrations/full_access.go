package integrationplugins

func init() {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	methodMap := make(map[string]RequestConstraint, len(methods))
	for _, m := range methods {
		methodMap[m] = RequestConstraint{}
	}
	RegisterCapability(GlobalIntegration, DangerouslyAllowFullAccess, CapabilitySpec{
		Generate: func(map[string]interface{}) ([]CallRule, error) {
			rule := CallRule{Path: "/**", Methods: methodMap}
			return []CallRule{rule}, nil
		},
	})
}
