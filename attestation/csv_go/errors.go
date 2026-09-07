package csvgo

import "errors"

var (
	ErrUnsupported     = errors.New("csv_go: unsupported operation")
	ErrShortBuffer     = errors.New("csv_go: buffer too short")
	ErrInvalidNonce    = errors.New("csv_go: invalid nonce length")
	ErrInvalidUserData = errors.New("csv_go: invalid user data")
	ErrSessionMAC      = errors.New("csv_go: session MAC verification failed")
	ErrMNonceMismatch  = errors.New("csv_go: report mnonce does not match request nonce")
)
