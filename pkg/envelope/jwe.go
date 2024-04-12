package envelope

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/samber/lo"
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
	encryptionAlgorithms := lo.Uniq(
		lo.Map(in.Recipients, func(i JWERecipient, _ int) jwa.KeyEncryptionAlgorithm {
			return jwa.KeyEncryptionAlgorithm(i.Header.Alg)
		}),
	)
	if len(encryptionAlgorithms) == 0 {
		encryptionAlgorithms = append(encryptionAlgorithms, jwa.KeyEncryptionAlgorithm(in.Header.Alg))
	}

	options := make([]jwe.DecryptOption, 0, len(keys)*len(encryptionAlgorithms))
	for _, key := range keys {
		for _, alg := range encryptionAlgorithms {
			switch alg {
			case jwa.ECDH_ES_A128KW, jwa.ECDH_ES_A192KW, jwa.ECDH_ES_A256KW:
				if _, ok := key.(*ecdsa.PrivateKey); ok {
					options = append(options, jwe.WithKey(alg, key))
				}
			case jwa.RSA1_5, jwa.RSA_OAEP, jwa.RSA_OAEP_256:
				if _, ok := key.(*rsa.PrivateKey); ok {
					options = append(options, jwe.WithKey(alg, key))
				}
			}
		}
	}

	jweRaw, _ := json.Marshal(in)
	return jwe.Decrypt(jweRaw, options...)
}
