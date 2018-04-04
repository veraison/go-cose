

install:
	dep ensure || echo "go dep not found (try https://golang.github.io/dep/docs/installation.html)"
	mkdir -p test
	cd test && git clone https://github.com/cose-wg/Examples.git cose-wg-examples || true
	cd test && git clone https://github.com/g-k/cose-rust.git || true
	cd test/cose-rust && git checkout test-verify-cli

lint:
	golint

vet:
	go vet

coverage:
	go test -coverprofile=coverage.out && go tool cover -html=coverage.out

what-todo:
	rg -g '**/*.go' -i TODO

util/data:
	mkdir -p util/data

util/data/tags.csv: util/data
	cd util/data && wget 'https://www.iana.org/assignments/cbor-tags/tags.csv'

util/data/algorithms.csv: util/data
	cd util/data && wget 'https://www.iana.org/assignments/cose/algorithms.csv'

util/data/elliptic-curves.csv: util/data
	cd util/data && wget 'https://www.iana.org/assignments/cose/elliptic-curves.csv'

iana-csvs: util/data/tags.csv util/data/algorithms.csv util/data/elliptic-curves.csv

golint:
	go get -u golang.org/x/lint/golint

godep:
	curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

goveralls:
	go get -u github.com/mattn/goveralls

smoketest-examples:
	go run example/sign.go
	go run example/verify.go

ci: godep golint goveralls install coverage smoketest-examples lint vet
	goveralls -coverprofile=coverage.out -service=travis-ci -repotoken $(COVERALLS_TOKEN)
