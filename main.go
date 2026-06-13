package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/uuk020/fileEncryption/internal"
)

func main() {
	config, err := internal.ParseFlags(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			return
		}
		log.Fatal(err)
	}

	if err := internal.ValidateCLI(*config); err != nil {
		log.Fatal(err)
	}

	normalizedMode, _ := internal.NormalizeMode(config.Mode)
	isEncryption := normalizedMode == "encrypt"

	password, err := internal.GetPassword(*config, isEncryption)
	if err != nil {
		log.Fatal(err)
	}

	if isEncryption {
		if config.Dir != "" {
			result, err := internal.EncryptDirConcurrent(config.Dir, password, 0)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("All files in the directory encrypted successfully! (%d files, %d skipped)\n", len(result.Success), len(result.Skipped))
			if config.Delete {
				for _, f := range result.Success {
					_ = os.Remove(f)
				}
				fmt.Printf("Deleted %d original files\n", len(result.Success))
			}
		} else if config.File != "" {
			err := internal.EncryptFileNew(config.File, password)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("File encrypted successfully (new AES-256-GCM format)")
			if config.Delete {
				if err := os.Remove(config.File); err == nil {
					fmt.Println("Deleted original file")
				}
			}
		}
	} else {
		if config.Dir != "" {
			result, err := internal.DecryptDirConcurrent(config.Dir, password, 0)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("All files in the directory decrypted successfully! (%d files, %d skipped)\n", len(result.Success), len(result.Skipped))
			for _, f := range result.Success {
				_ = os.Remove(f)
			}
			fmt.Printf("Deleted %d encrypted files\n", len(result.Success))
		} else if config.File != "" {
			err := internal.DecryptFileAuto(config.File, password)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("File decrypted successfully")
			if err := os.Remove(config.File); err == nil {
				fmt.Println("Deleted encrypted file")
			}
		}
	}
}