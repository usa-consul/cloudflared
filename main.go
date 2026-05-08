// cloudflared - A tunnel client for Cloudflare's network
// This is a fork of cloudflare/cloudflared with additional features and fixes.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

var (
	// Version is set at build time via ldflags
	Version = "dev"
	// BuildTime is set at build time via ldflags
	BuildTime = "unknown"
	// GitCommit is set at build time via ldflags
	GitCommit = "none"
)

func main() {
	// Configure zerolog with human-friendly console output
	// Using time.RFC3339 instead of time.Kitchen so timestamps include the date,
	// which is more useful when reviewing logs after the fact.
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	})

	app := &cli.App{
		Name:    "cloudflared",
		Usage:   "Cloudflare Tunnel client",
		Version: fmt.Sprintf("%s (built: %s, commit: %s)", Version, BuildTime, GitCommit),
		Authors: []*cli.Author{
			{
				Name:  "Cloudflare",
				Email: "support@cloudflare.com",
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to configuration file",
				EnvVars: []string{"TUNNEL_CONFIG"},
			},
			&cli.BoolFlag{
				Name:    "debug",
				Usage:   "Enable debug logging",
				EnvVars: []string{"TUNNEL_DEBUG"},
			},
			&cli.StringFlag{
				Name:  "loglevel",
				// Changed default from "info" to "warn" to reduce noise in normal operation.
				// Use --loglevel=info or --debug to get more verbose output when needed.
				Value:   "warn",
				Usage:   "Log level (debug, info, warn, error, fatal)",
				EnvVars: []string{"TUNNEL_LOGLEVEL"},
			},
		},
		Before: func(c *cli.Context) error {
			if c.Bool("debug") {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
				return nil
			}

			level, err := zerolog.ParseLevel(c.String("loglevel"))
			if err != nil {
				return fmt.Errorf("invalid log level %q: %w", c.String("loglevel"), err)
			}
			zerolog.SetGlobalLevel(level)
			return nil
		},
		Action: func(c *cli.Context) error {
			// Default action: show help
			return cli.ShowAppHelp(c)
		},
		// ExitErrHandler suppresses the default "exit status 1" message that cli
		// prints when an action returns an error, since we already log it via
		// log.Fatal below.
		ExitErrHandler: func(c *cli.Context, err error) {},
		// Suggest similar commands when a user mistypes a subcommand name.
		// Handy for muscle-memory mistakes like "tunel" instead of "tunnel".
		SuggestAfterError: true,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("cloudflared exited with error")
	}
}
