package main

import (
	impl "github.com/austinippon/gloo-plugins/plugins/customerio_auth_plugin/pkg"
	"github.com/solo-io/ext-auth-plugins/api"
)

func main() {}

// Compile-time assertion
var _ api.ExtAuthPlugin = new(impl.CustomerIOAuthPlugin)

// This is the exported symbol that Gloo will look for.
//noinspection GoUnusedGlobalVariable
var Plugin impl.CustomerIOAuthPlugin
