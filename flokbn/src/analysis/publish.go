package analysis

import (
	"fmt"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/jail"
	"github.com/ChristianF88/flokbn/output"
	"github.com/ChristianF88/flokbn/pools"
)

// publishJailAndBans runs the jail update and ban-file publish step when both a
// jail file and a ban file are configured; otherwise it is a no-op. Shared by
// every successful exit of both static entrypoints (including the empty-log
// exits) so the ban file is refreshed on each run.
//
// Fail loud: a jail/ban processing failure must not exit 0 with no ban file.
// The barrier (Config.Validate) catches an unloadable jail before this; the
// propagation is defense-in-depth for the remaining causes (jail save /
// ban-file write).
func publishJailAndBans(cfg *config.Config, jsonOutput *output.JSONOutput) error {
	if cfg.Global == nil || cfg.Global.JailFile == "" || cfg.Global.BanFile == "" {
		return nil
	}
	if err := ProcessJailWithWhitelist(cfg, jsonOutput); err != nil {
		jsonOutput.AddError("jail_processing", fmt.Sprintf("Failed to process jail with whitelist/blacklist: %v", err), 1)
		return err
	}
	return nil
}

// ProcessJailWithWhitelist processes jail updates with whitelist/blacklist filtering
func ProcessJailWithWhitelist(cfg *config.Config, jsonOutput *output.JSONOutput) error {
	if cfg.Global == nil {
		return fmt.Errorf("global configuration is required for jail processing")
	}

	// Load whitelist and blacklist
	whitelistCIDRs, err := cfg.LoadWhitelistCIDRs()
	if err != nil {
		jsonOutput.AddError("whitelist_load", fmt.Sprintf("Failed to load whitelist: %v", err), 1)
		return err
	}
	blacklistCIDRs, err := cfg.LoadBlacklistCIDRs()
	if err != nil {
		jsonOutput.AddError("blacklist_load", fmt.Sprintf("Failed to load blacklist: %v", err), 1)
		return err
	}

	// Collect all CIDRs from all tries that are marked for jail
	allJailCIDRs := pools.Pools.GetStringSlice()
	defer pools.Pools.ReturnStringSlice(allJailCIDRs)
	for _, trieResult := range jsonOutput.Tries {
		for i, clusterResult := range trieResult.Data {
			if len(trieResult.Parameters.UseForJail) > i && trieResult.Parameters.UseForJail[i] {
				for _, mergedRange := range clusterResult.MergedRanges {
					allJailCIDRs = append(allJailCIDRs, mergedRange.CIDR)
				}
			}
		}
	}

	// Combine CIDR whitelist and User-Agent-whitelisted IPs into one list:
	// every whitelist source must win everywhere (pre-jail filter and the
	// final publish pass below).
	allWhitelists := pools.Pools.GetStringSlice()
	defer pools.Pools.ReturnStringSlice(allWhitelists)
	allWhitelists = append(allWhitelists, whitelistCIDRs...)
	for _, ip := range jsonOutput.UserAgentWhitelistIPs {
		allWhitelists = append(allWhitelists, ip+"/32")
	}

	// Drop jail CIDRs fully covered by the whitelist, keeping the rest whole.
	// Partial overlaps are NOT fragmented here - the whitelist is applied
	// exactly at the publish choke point (ComposeBanLists below). Fragmenting
	// here around UA-whitelisted /32s would explode a handful of jail ranges
	// into tens of thousands of CIDRs and feed a super-linear jail update.
	filteredJailCIDRs, removedCount := cidr.DropFullyWhitelisted(allJailCIDRs, allWhitelists)

	// Log whitelist filtering results
	if len(allWhitelists) > 0 && removedCount > 0 {
		jsonOutput.AddWarning("whitelist_applied", fmt.Sprintf("Whitelist filtering prevented %d CIDRs from being added to jail", removedCount), 0)
	}

	// Load existing jail
	jailInstance, err := jail.FileToJail(cfg.GetJailFile())
	if err != nil {
		jsonOutput.AddError("jail_load", fmt.Sprintf("Failed to load jail %q: %v", cfg.GetJailFile(), err), 1)
		return err
	}

	// Add User-Agent blacklisted IPs to jail
	userAgentBlacklistCIDRs := pools.Pools.GetStringSlice()
	defer pools.Pools.ReturnStringSlice(userAgentBlacklistCIDRs)
	if len(jsonOutput.UserAgentBlacklistIPs) > 0 {
		for _, ip := range jsonOutput.UserAgentBlacklistIPs {
			userAgentBlacklistCIDRs = append(userAgentBlacklistCIDRs, ip+"/32")
		}
		filteredJailCIDRs = append(filteredJailCIDRs, userAgentBlacklistCIDRs...)
	}

	// Expire run-out bans on EVERY run, not only when there is something to add:
	// ListActiveBans below trusts the BanActive flags, and jail.Update (the only
	// other caller of UpdateBanActiveStatus) is skipped when nothing was
	// detected - a quiet run would otherwise republish expired bans from the
	// persisted flags indefinitely. Expiry only flips active -> inactive, so a
	// count delta is an exact change signal (same check as the live heartbeat).
	activeBefore := len(jailInstance.ListActiveBans())
	jailInstance.UpdateBanActiveStatus()
	bansExpired := len(jailInstance.ListActiveBans()) != activeBefore

	// Update jail with filtered CIDRs
	if len(filteredJailCIDRs) > 0 {
		if err := jailInstance.Update(filteredJailCIDRs); err != nil {
			jsonOutput.AddWarning("jail_update", fmt.Sprintf("Some CIDRs failed during jail update: %v", err), 1)
		}
	}

	// Persist when the jail changed: new detections, or bans that just expired.
	if len(filteredJailCIDRs) > 0 || bansExpired {
		err = jail.JailToFile(jailInstance, cfg.GetJailFile())
		if err != nil {
			jsonOutput.AddError("jail_save", fmt.Sprintf("Failed to save jail %q: %v", cfg.GetJailFile(), err), 1)
			return err
		}
	}

	// Always generate ban file from jail. ComposeBanLists is the publish
	// choke point: whitelists win over active bans AND the manual blacklist.
	activeBans := jailInstance.ListActiveBans()
	publishBans, publishBlacklist := cidr.ComposeBanLists(activeBans, blacklistCIDRs, allWhitelists)

	err = jail.WriteBanFileWithBlacklist(cfg.GetBanFile(), publishBans, publishBlacklist)
	if err != nil {
		jsonOutput.AddError("banfile_write", fmt.Sprintf("Failed to write ban file %q: %v", cfg.GetBanFile(), err), 1)
		return err
	}

	if len(publishBlacklist) > 0 {
		jsonOutput.AddWarning("blacklist_applied", fmt.Sprintf("Added %d manual blacklist entries to ban file", len(publishBlacklist)), 0)
	}

	return nil
}
