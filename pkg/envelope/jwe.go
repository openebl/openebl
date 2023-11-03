package envelope

import (
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

type KeyEncryptionSetting struct {
	PublicKey any
	Algorithm KeyEncryptionAlgorithm
}

func Encrypt(payload []byte, enc ContentEncryptionAlgorithm, keySettings []KeyEncryptionSetting) (JWE, error) {
	options := make([]jwe.EncryptOption, len(keySettings)+2)
	for i, ks := range keySettings {
		options[i] = jwe.WithKey(jwa.KeyEncryptionAlgorithm(ks.Algorithm), ks.PublicKey)
	}
	options[len(keySettings)] = jwe.WithContentEncryption(jwa.ContentEncryptionAlgorithm(enc))
	options[len(keySettings)+1] = jwe.WithJSON()

	output, err := jwe.Encrypt(payload, options...)
	if err != nil {
		return JWE{}, err
	}

	jweResult := JWE{}
	if err := json.Unmarshal(output, &jweResult); err != nil {
		return JWE{}, err
	}
	return jweResult, nil
}

func Decrypt(in JWE, keys []any) ([]byte, error) {
	options := make([]jwe.DecryptOption, 0, len(keys)*(len(in.Recipients)+1))

	// TODO: Generate WithKey options based on the compatibility between the keys and the key encryption algorithm.
	for _, key := range keys {
		for _, r := range in.Recipients {
			options = append(options, jwe.WithKey(jwa.KeyEncryptionAlgorithm(r.Header.Alg), key))
		}
		if len(in.Recipients) == 0 {
			options = append(options, jwe.WithKey(jwa.KeyEncryptionAlgorithm(in.Header.Alg), key))
		}
	}

	jweRaw, _ := json.Marshal(in)
	return jwe.Decrypt(jweRaw, options...)
}
