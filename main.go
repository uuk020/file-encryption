package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/uuk020/fileEncryption/internal"
)

func main() {
	mode := flag.String("m", "encryption", "encryption or decryption mode")
	password := flag.String("p", "", "input password, same password will be used to encrypt and decrypt")
	file := flag.String("f", "", "input file, encrypted file will be stored with .xu extension")

	flag.Parse()

	if *file == "" {
		log.Fatal("file are required")
	}

	if *password == "" {
		log.Fatal("code is required")
	}

	if *mode == "encryption" {
		err := internal.EncryptFile(*file, *password)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("File encypted successfully, remember delete the original file!")
	} else if *mode == "decryption" {
		err := internal.DecryptFile(*file, *password)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("File decrypted successfully!")
	} else {
		log.Fatal("mode must be encrypt or decrypt")
	}

}
