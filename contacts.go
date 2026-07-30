package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// contactsFilePath returns the path to the contacts JSON file.
func contactsFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".veil-contacts.json"
	}
	return filepath.Join(home, ".veil", "contacts.json")
}

// LoadContacts reads the contacts file from disk.
// Returns an empty map (not an error) if the file doesn't exist yet.
func LoadContacts() (map[string]string, error) {
	data, err := os.ReadFile(contactsFilePath())
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read contacts: %w", err)
	}
	var contacts map[string]string
	if err := json.Unmarshal(data, &contacts); err != nil {
		return nil, fmt.Errorf("failed to parse contacts: %w", err)
	}
	return contacts, nil
}

// SaveContacts writes the contacts map to disk atomically.
func SaveContacts(contacts map[string]string) error {
	path := contactsFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create contacts directory: %w", err)
	}
	data, err := json.MarshalIndent(contacts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize contacts: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// AddContact saves a nickname → address mapping to disk.
// The address is stored without the ".onion" suffix.
// The nickname is normalized to lowercase.
func AddContact(name, address string) error {
	contacts, err := LoadContacts()
	if err != nil {
		return err
	}
	contacts[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSuffix(strings.TrimSpace(address), ".onion")
	return SaveContacts(contacts)
}

// RemoveContact deletes a contact by nickname.
func RemoveContact(name string) error {
	contacts, err := LoadContacts()
	if err != nil {
		return err
	}
	key := strings.ToLower(strings.TrimSpace(name))
	if _, exists := contacts[key]; !exists {
		return fmt.Errorf("contact %q not found", key)
	}
	delete(contacts, key)
	return SaveContacts(contacts)
}

// LookupNickname returns the nickname for a given onion address, or "" if not found.
func LookupNickname(contacts map[string]string, address string) string {
	address = strings.TrimSuffix(address, ".onion")
	for name, addr := range contacts {
		if addr == address {
			return name
		}
	}
	return ""
}
