module sqyrrl

go 1.22

require (
	github.com/alexedwards/scs/v2 v2.8.0
	github.com/coreos/go-oidc/v3 v3.11.0
	github.com/cyverse/go-irodsclient v0.14.4
	github.com/microcosm-cc/bluemonday v1.0.26
	github.com/onsi/ginkgo/v2 v2.20.1
	github.com/onsi/gomega v1.34.1
	github.com/rs/xid v1.5.0
	github.com/rs/zerolog v1.33.0
	github.com/spf13/cobra v1.8.1
	golang.org/x/oauth2 v0.22.0
	golang.org/x/term v0.23.0
)

require (
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/tools v0.24.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// replace github.com/cyverse/go-irodsclient => ../go-irodsclient

replace github.com/cyverse/go-irodsclient => github.com/wtsi-npg/go-irodsclient v0.0.0-20240417120912-4a4dec5bcefb
