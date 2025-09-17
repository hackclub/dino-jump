package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Open database
	db, err := sql.Open("sqlite3", "./tokens.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	// Load encryption key
	keyData, err := os.ReadFile(".encrypt_key")
	if err != nil {
		log.Fatal("Failed to read encryption key:", err)
	}
	encryptKey, err := hex.DecodeString(string(keyData))
	if err != nil {
		log.Fatal("Failed to decode encryption key:", err)
	}

	// Query all stored tokens
	rows, err := db.Query("SELECT user_id, username, encrypted_xoxc_token, encrypted_xoxd_cookie FROM slack_browser_tokens")
	if err != nil {
		log.Fatal("Failed to query tokens:", err)
	}
	defer rows.Close()

	fmt.Println("=== Slackdump Commands ===\n")

	for rows.Next() {
		var userID, username, encryptedXoxc, encryptedXoxd string
		err := rows.Scan(&userID, &username, &encryptedXoxc, &encryptedXoxd)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		// Decrypt tokens
		xoxcToken, err := decrypt(encryptedXoxc, encryptKey)
		if err != nil {
			log.Printf("Failed to decrypt xoxc token for %s: %v", username, err)
			continue
		}

		xoxdCookie, err := decrypt(encryptedXoxd, encryptKey)
		if err != nil {
			log.Printf("Failed to decrypt xoxd cookie for %s: %v", username, err)
			continue
		}

		// Generate slackdump setup for this user
		fmt.Printf("# User: %s (%s)\n", username, userID)
		
		// Create environment file for this user (using userID for uniqueness)
		fmt.Printf("# Create .env file for %s:\n", userID)
		fmt.Printf("cat > %s.env << 'EOF'\n", userID)
		fmt.Printf("SLACK_TOKEN=%s\n", xoxcToken)
		fmt.Printf("COOKIE=d=%s\n", xoxdCookie)
		fmt.Printf("EOF\n\n")
		
		// Show how to use the tokens with slackdump
		fmt.Printf("# Then use the environment file:\n")
		fmt.Printf("# Load environment:\n")
		fmt.Printf("source %s.env\n\n", userID)
		
		fmt.Printf("# Or run with environment inline:\n")
		fmt.Printf("env $(cat %s.env | xargs) slackdump help\n", userID)
		fmt.Printf("\n# List all channels/conversations:\n")
		fmt.Printf("env $(cat %s.env | xargs) slackdump list channels > %s_channels.txt\n", userID, userID)
		fmt.Printf("\n# Archive everything:\n")
		fmt.Printf("env $(cat %s.env | xargs) slackdump archive %s_archive\n", userID, userID)
		fmt.Printf("\n# Archive ONLY private channels/DMs:\n")
		fmt.Printf("# 1. Filter private channels (D=DMs, G=group messages):\n")
		fmt.Printf("grep '^[DG]' %s_channels.txt | cut -f1 > %s_private.txt\n", userID, userID)
		fmt.Printf("# 2. Archive only private conversations:\n")
		fmt.Printf("env $(cat %s.env | xargs) slackdump archive @%s_private.txt %s_private_archive\n", userID, userID, userID)
		
		// Show raw token values for manual setup if needed
		fmt.Printf("# Raw values (for manual setup):\n")
		fmt.Printf("# SLACK_TOKEN=%s\n", xoxcToken)
		fmt.Printf("# COOKIE=d=%s\n", xoxdCookie)
		
		fmt.Println("---")
	}

	if err = rows.Err(); err != nil {
		log.Fatal("Error iterating rows:", err)
	}
}

func decrypt(ciphertext string, key []byte) (string, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext_bytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext_bytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
