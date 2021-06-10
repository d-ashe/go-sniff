package cmd

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	c "github.com/d-ashe/go-sniff/config"
	//"github.com/d-ashe/pkg/go-sniff"
)

var (
	// Used for flags.
	cfgFile string
	v       string
	rootCmd = &cobra.Command{
		Use:   "go-sniff",
		Short: "go-sniff decodes packets and inserts to elasticsearch",
		Long:  `go-sniff decodes packets and inserts to elasticsearch`,
		Run: func(cmd *cobra.Command, args []string) {
			var configuration c.Configurations
			err := viper.Unmarshal(&configuration)
			if err != nil {
				logrus.Error("Unable to decode into config struct, %v", err)
			}
			run(configuration.Database.Conn, configuration.Node.Host, configuration.Node.Path)
		},
	}
)

func SniffCmd() *cobra.Command {
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := setUpLogs(os.Stdout, v); err != nil {
			return err
		}
		return nil
	}
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /go/src/go-sniff/config.yml)")
	rootCmd.PersistentFlags().StringVarP(&v, "verbosity", "v", logrus.WarnLevel.String(), "Log level (debug, info, warn, error, fatal, panic")

	return rootCmd
}

func setUpLogs(out io.Writer, level string) error {
	logrus.SetOutput(out)
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)
	return nil
}

func initConfig() {
	// Don't forget to read config either from cfgFile or from home directory!
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath("/go/src/go-sniff")
		viper.SetConfigName("config.yml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
	}
}