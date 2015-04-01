// Logs sifts through nginx logs and spits out a JSON representation of what URLs attackers try to get to,
// their

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"

	"github.com/codegangsta/cli"
    "encoding/json"
)

var (
	attackers     = make(map[string]interface{})
	attacks = make(map[string]interface{})
	totals = make(map[string]interface{})
	urls = make(map[string]int)
	methods = make(map[string]int)
	interestingRequests = make(map[string]int)
	sshLogPattern = regexp.MustCompile(`^auth.log(\.\d+)?$`)
)

func main() {
	app := cli.NewApp()
	app.Name = "logs"
	app.Usage = "sift through nginx logs"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "dir",
			Usage: "log directory",
		},
	}

	app.Action = func(c *cli.Context) {
		if !c.IsSet("dir") {
			// Print out the help if no directory was specified
			fmt.Fprintln(os.Stderr, "No directory specified")
			c.App.Command("help").Action(c)
			os.Exit(-1)
		}

		dir := c.String("dir")
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Invalid directory: %s\n", dir)
			} else {
				fmt.Fprintln(os.Stderr, err)
			}

			os.Exit(-1)
		}

		totals["methods"] = methods
		totals["urls"] = urls
		attackers["attacks"] = attacks
		attackers["totals"] = totals
		attackers["interesting_requests"] = interestingRequests

		for _, fileInfo := range files {
			// Ignore directories and files we don't care about
			if fileInfo.IsDir() ||
				(!NginxLogPattern.MatchString(fileInfo.Name()) && !sshLogPattern.MatchString(fileInfo.Name())) {
				continue
			}

			file, err := os.Open(filepath.Join(dir, fileInfo.Name()))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not open file: %s", err)
				continue
			}
			defer file.Close()

            if NginxLogPattern.MatchString(fileInfo.Name()) {
			    ReadNginxLog(file)
            }
		}

        encoded, _ := json.MarshalIndent(attackers, "", "    ")

        fmt.Println(string(encoded))
	}

    app.Run(os.Args)
}
