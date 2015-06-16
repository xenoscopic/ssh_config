package main

import (
	"log"
	"os"

	"github.com/jasonmoo/ssh_config"
)

func main() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// ensure file is opened for read/write
	file, err := os.OpenFile(os.ExpandEnv("$HOME/.ssh/config"), os.O_RDWR, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	config, err := ssh_config.Parse(file)
	if err != nil {
		log.Fatal(err)
	}

	// modify by reference for existing params
	// or create a new param and append it to global
	if param := config.GetParam(ssh_config.VisualHostKeyKeyword); param != nil {
		param.Args = "yes"
	} else {
		param = ssh_config.NewParam(ssh_config.VisualHostKeyKeyword, "yes", []string{"good to see you"})
		config.Globals = append(config.Globals, param)
	}

	// grab host by name and set param
	if host := config.GetHost("dev"); host != nil {
		if param := host.GetParam(ssh_config.UserKeyword); param != nil {
			param.Args = "ubuntu"
		} else {
			param = ssh_config.NewParam(ssh_config.UserKeyword, "ubuntu", nil)
			host.Params = append(host.Params, param)
		}
	}

	// write to file with built-in fallback to original source on error
	if err := config.WriteToFile(file); err != nil {
		log.Fatal(err)
	}

}
