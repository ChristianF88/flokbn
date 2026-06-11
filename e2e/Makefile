.PHONY: all static filters whitelist-blacklist live live-detection live-firewall clean

# Run all tests that don't require Docker
all: static filters whitelist-blacklist

# Run the basic static analysis E2E test
static:
	@bash e2e_static_test.sh

# Run the filtering scenarios E2E test (UA, endpoint, time, combined)
filters:
	@bash e2e_static_filters_test.sh

# Run the whitelist/blacklist E2E test
whitelist-blacklist:
	@bash e2e_static_whitelist_blacklist_test.sh

# Run the basic live mode E2E test (requires Docker)
live:
	@bash e2e_live_test.sh

# Run the live mode multi-trie detection test (requires Docker)
live-detection:
	@bash e2e_live_detection_test.sh

# Run the closed-loop firewall overlay test (requires Docker)
live-firewall:
	@bash e2e_docker_firewall_test.sh

# Run everything including Docker tests
everything: all live live-detection live-firewall

clean:
	@echo "Nothing to clean"
