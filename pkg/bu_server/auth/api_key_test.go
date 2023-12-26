package auth_test

import (
	"testing"

	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/stretchr/testify/assert"
)

func TestAPIKeyGenerating(t *testing.T) {
	apiKeyString, err := auth.NewAPIKeyString()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("API key string: %s", apiKeyString)

	apiKeyHashedString1, err := apiKeyString.Hash()
	if err != nil {
		t.Fatal(err)
	}
	apiKeyHashedString2, err := apiKeyString.Hash()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("API key hashed string1: %s", apiKeyHashedString1)
	t.Logf("API key hashed string2: %s", apiKeyHashedString2)
	assert.NotEqual(t, apiKeyHashedString1, apiKeyHashedString2)

	assert.NoError(t, auth.VerifyAPIKeyString(apiKeyString, apiKeyHashedString1))
	assert.NoError(t, auth.VerifyAPIKeyString(apiKeyString, apiKeyHashedString2))

	assert.ErrorIs(t, auth.VerifyAPIKeyString(apiKeyString+"a", auth.APIKeyHashedString(apiKeyHashedString1)), auth.ErrMismatchAPIKey)
}
