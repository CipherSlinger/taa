module teecrypto

go 1.22

require (
	github.com/CipherSlinger/teeaudit v0.0.0-00010101000000-000000000000
	github.com/tjfoc/gmsm v1.4.1
)

replace github.com/CipherSlinger/teeaudit => ../../teeaudit

// teeaudit's own replace for teetls does not reach this module: replace
// directives are honoured only in the main module, so a standalone build of
// the SDK needs its own.
replace github.com/CipherSlinger/teetls => ../../teellm/teetls
