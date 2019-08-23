package cmd

type Errors struct {
	Errors []string `json:"errors"`
}

type Token struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          interface{} `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          Auth        `json:"auth"`
}

type Auth struct {
	ClientToken   string   `json:"client_token"`
	Accessor      string   `json:"accessor"`
	Policies      []string `json:"policies"`
	TokenPolicies []string `json:"token_policies"`
	Metadata      struct {
		Role                     string `json:"role"`
		ServiceAccountName       string `json:"service_account_name"`
		ServiceAccountNamespace  string `json:"service_account_namespace"`
		ServiceAccountSecretName string `json:"service_account_secret_name"`
		ServiceAccountUID        string `json:"service_account_uid"`
	} `json:"metadata"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
	EntityID      string `json:"entity_id"`
	TokenType     string `json:"token_type"`
	Orphan        bool   `json:"orphan"`
}
