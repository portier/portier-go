package main

import (
	"bufio"
	"log"
	"os"
	"strings"

	"github.com/portier/portier-go"
)

const verifyEndpoint = "http://imaginary-client.test/fake-verify-route"

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Broker required")
	}

	client, err := portier.NewClient(&portier.Config{
		Broker:      os.Args[1],
		RedirectURI: verifyEndpoint,
	})
	if err != nil {
		log.Fatal("portier.NewClient error:", err)
	}

	writeLine := func(cmd ...string) {
		_, err := os.Stdout.WriteString(strings.Join(cmd, "\t") + "\n")
		if err != nil {
			log.Fatal("stdout error", err)
		}
	}

	stdin := bufio.NewScanner(os.Stdin)
	for stdin.Scan() {
		cmd := strings.Split(stdin.Text(), "\t")
		switch cmd[0] {
		case "echo":
			writeLine("ok", cmd[1])
		case "auth":
			url, err := client.StartAuth(cmd[1])
			if err != nil {
				writeLine("err", err.Error())
			} else {
				writeLine("ok", url)
			}
		case "verify":
			email, err := client.Verify(cmd[1])
			if err != nil {
				writeLine("err", err.Error())
			} else {
				writeLine("ok", email)
			}
		default:
			log.Fatal("invalid command:", cmd)
		}
	}
	if err := stdin.Err(); err != nil {
		log.Fatal(err)
	}
}
