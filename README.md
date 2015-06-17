# ssh_config
a simple ssh config parser/writer lib


Example:

```go
ssh_config_file := os.ExpandEnv("$HOME/.ssh/config")

file, err := os.Open(ssh_config_file)
if err != nil {
	log.Fatal(err)
}

config, err := ssh_config.Parse(file)
if err != nil {
	log.Fatal(err)
}

file.Close()

// modify by reference for existing params
// or create a new param and append it to global
if param := config.GetParam(ssh_config.VisualHostKeyKeyword); param != nil {
	param.Args = []string{"yes"}
} else {
	param = ssh_config.NewParam(ssh_config.VisualHostKeyKeyword, []string{"yes"}, []string{"good to see you"})
	config.Globals = append(config.Globals, param)
}

// atomic write to file to ensure config is preserved in
// the event of an error
if err := config.WriteToFilepath(ssh_config_file); err != nil {
	log.Fatal(err)
}
```

[Documentation](https://godoc.org/github.com/jasonmoo/ssh_config)

License: MIT