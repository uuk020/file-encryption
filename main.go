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
	file := flag.String("f", "", "input file, encrypted or decrypted file")
	dir := flag.String("d", "", "input directory, all files in the directory will be encrypted or decrypted")

	flag.Parse()

	if *dir == "" {
		if *file == "" {
			log.Fatal("file or directory are required")
		}
	} else {
		if *file != "" {
			log.Fatal("file or directory are required")
		}
	}

	if *password == "" {
		log.Fatal("code is required")
	}

	key := internal.GenerateKey(*password, 16)
	if *mode == "encryption" {
		if *dir != "" {
			err := internal.EncryptDir(*dir, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("All files in the directory encypted successfully, remember delete the original files!")
		} else if *file != "" {
			err := internal.EncryptFile(*file, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("File encypted successfully, remember delete the original file!")
		}
	} else if *mode == "decryption" {
		if *dir != "" {
			err := internal.DecryptDir(*dir, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("All files in the directory decrypted successfully!")
		} else if *file != "" {
			err := internal.DecryptFile(*file, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("File decrypted successfully!")
		}
	} else {
		log.Fatal("mode must be encrypt or decrypt")
	}

}
