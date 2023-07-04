module github.com/veraison/go-cose

go 1.18

require github.com/fxamacker/cbor/v2 v2.4.0

require github.com/x448/float16 v0.8.4 // indirect

retract (
	v1.2.1 // contains retractions only
	v1.2.0 // published in error
)
