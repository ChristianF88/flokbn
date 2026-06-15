package config

import (
	"fmt"
	"github.com/ChristianF88/flokbn/cidr"
)

// CreateUserAgentMatcher creates a fast UserAgentMatcher from config files
// This is the recommended way to create a UserAgentMatcher for optimal performance
func (c *Config) CreateUserAgentMatcher() (*cidr.UserAgentMatcher, error) {
	// Load whitelist patterns
	whitelistPatterns, err := c.LoadUserAgentWhitelistPatterns()
	if err != nil {
		return nil, fmt.Errorf("failed to load User-Agent whitelist: %w", err)
	}

	// Load blacklist patterns
	blacklistPatterns, err := c.LoadUserAgentBlacklistPatterns()
	if err != nil {
		return nil, fmt.Errorf("failed to load User-Agent blacklist: %w", err)
	}

	// Create and return the matcher
	return cidr.NewUserAgentMatcher(whitelistPatterns, blacklistPatterns), nil
}
