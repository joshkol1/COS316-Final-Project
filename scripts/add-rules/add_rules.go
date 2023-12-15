package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var command string
	var rules_file_name string

	flag.StringVar(&command, "command", "", "iptables command to write to rules file")
	flag.StringVar(&rules_file_name, "file", "iptables-clone.rules", "name of rules file to write to")
	flag.Parse()
	if command == "" {
		flag.PrintDefaults()
		return
	}
	
	file, err := os.OpenFile(rules_file_name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(command+"\n")
	if err != nil {
		fmt.Println("Error writing to file: ", err)
		return
	}
	fmt.Println("Added rule to file", rules_file_name)
}