module sqyrrl

go 1.24

require (
	github.com/BurntSushi/toml v1.5.0
	github.com/alexedwards/scs/v2 v2.8.0
	github.com/coreos/go-oidc/v3 v3.13.0
	github.com/cyverse/go-irodsclient v0.15.7-0.20241106203458-0b74740d1c86
	github.com/microcosm-cc/bluemonday v1.0.27
	github.com/onsi/ginkgo/v2 v2.23.4
	github.com/onsi/gomega v1.37.0
	github.com/rs/xid v1.6.0
	github.com/rs/zerolog v1.34.0
	github.com/spf13/cobra v1.9.1
	golang.org/x/oauth2 v0.30.0
	golang.org/x/term v0.31.0
)

require (
	github.com/go-jose/go-jose/v3 v3.0.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.0 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
)

require (
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20250403155104-27863c87afa6 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/oauth2-proxy/mockoidc v0.0.0-20240214162133-caebfff84d25
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/tools v0.31.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// replace github.com/cyverse/go-irodsclient => ../go-irodsclient
replace github.com/cyverse/go-irodsclient => github.com/wtsi-npg/go-irodsclient v0.0.0-20250110165023-801d97d497e6
