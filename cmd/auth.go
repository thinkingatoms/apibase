/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package cmd

import (
	"github.com/thinkingatoms/apibase/ez"
	"github.com/thinkingatoms/apibase/servers"

	"github.com/spf13/cobra"
)

var configs *[]string

// authCmd represents the auth command
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		app := servers.NewServer(true)
		app.LoadConfig(configs)
		a := ez.ReturnOrPanic(servers.CreateAuth(app))
		servers.RegisterAuthService(app, a, "admin")
		ez.PanicIfErr(servers.RegisterStripeService(app, a))
		app.Serve()
	},
}

func init() {
	GetRootCmd().AddCommand(authCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// runCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	configs = authCmd.Flags().StringSliceP("config", "c",
		nil, "path/to/config[::specific.keys[,more.keys]]")
}
