package envelope

import "github.com/lestrrat-go/jwx/v2/jwa"

type SignatureAlgorithm jwa.SignatureAlgorithm                 // Algorithm represents the algorithm used for encryption or signature
type ContentEncryptionAlgorithm jwa.ContentEncryptionAlgorithm // ContentEncryptionAlgorithm represents the algorithm used for content encryption
type KeyEncryptionAlgorithm jwa.KeyEncryptionAlgorithm         // KeyEncryptionAlgorithm represents the algorithm used for key encryption
