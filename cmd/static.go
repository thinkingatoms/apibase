/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package cmd

import (
	"github.com/thinkingatoms/apibase/servers"

	"github.com/spf13/cobra"
)

var staticService = &struct {
	port    *int
	mapping *[]string
}{}

// staticCmd represents the static command
var staticCmd = &cobra.Command{
	Use:   "static",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		servers.ServeStaticFiles(*staticService.port, *staticService.mapping)
	},
}

func init() {
	GetRootCmd().AddCommand(staticCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// staticCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// staticCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	staticService.port = staticCmd.Flags().IntP("port", "p", 8000, "port to listen on")

	staticService.mapping = staticCmd.Flags().StringSliceP("mapping", "m",
		[]string{"/:/static"}, "server/path:/local/path")
}
