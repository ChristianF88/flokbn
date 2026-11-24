package analysis

import (
	"fmt"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/jail"
	"github.com/ChristianF88/flokbn/output"
)

// BanInput is one round of input for UpdateBans. All entries are IPv4 CIDR
// strings; the slices are read, never modified.
type BanInput struct {
	// Detected holds the merged ranges found by the cluster sets that feed the
	// jail. A range fully covered by a single Whitelist entry is dropped; any
	// other range enters the jail whole, even when it overlaps the whitelist
	// (see cidr.DropFullyWhitelisted for why it is not carved up here).
	Detected []string
	// ForceBan holds ranges that enter the jail without that whitelist check:
	// the IPs seen with a blacklisted User-Agent, as /32. The whitelist still
	// wins when the bans are published.
	ForceBan []string
	// Whitelist is every whitelist source combined: the CIDR whitelist file and
	// the IPs seen with a whitelisted User-Agent, as /32.
	Whitelist []string
	// Blacklist is the manual blacklist. It never enters the jail; it is
	// published next to the jail's active bans.
	Blacklist []string
}

// BanUpdate is the outcome of UpdateBans.
type BanUpdate struct {
	// Bans and Blacklist are the two lists to publish (ban file sections):
	// the jail's active bans and the manual blacklist, each with the whitelist
	// subtracted exactly (cidr.ComposeBanLists).
	Bans      []string
	Blacklist []string
	// WhitelistDropped is the number of Detected ranges the whitelist kept out
	// of the jail.
	WhitelistDropped int
	// Jailed is the number of ranges handed to the jail (Detected minus the
	// dropped ones, plus ForceBan).
	Jailed int
	// Expired is the number of bans that ran out in this round.
	Expired int
	// JailChanged reports that the jail needs persisting: ranges were handed to
	// it or bans ran out. It can be true for a round that re-detected only
	// ranges that are already banned.
	JailChanged bool
	// UpdateErr is set when the jail rejected some of the ranges. The others
	// were still applied, and Bans/Blacklist are valid.
	UpdateErr error
}

// UpdateBans runs one round of the ban pipeline on an in-memory jail:
//
//  1. drop detected ranges that are fully whitelisted,
//  2. expire bans that ran out (also when nothing was detected - the active
//     flags persisted with the jail are otherwise trusted forever),
//  3. hand the remaining ranges to the jail, which starts or escalates bans,
//  4. compose the lists to publish, where the whitelist wins over both the
//     active bans and the manual blacklist.
//
// It does no I/O: loading and saving the jail and writing the ban file belong
// to the caller (publishStatic below for static mode, liveLoop.publishBans in
// package cli for live mode, where a heartbeat is a round with nothing
// detected).
func UpdateBans(j *jail.Jail, in BanInput) BanUpdate {
	var toJail []string
	dropped := 0
	if len(in.Detected) > 0 {
		toJail, dropped = cidr.DropFullyWhitelisted(in.Detected, in.Whitelist)
	}
	if len(in.ForceBan) > 0 {
		// Cap the capacity: with an empty whitelist toJail is in.Detected
		// itself and must not be appended to in place.
		toJail = append(toJail[:len(toJail):len(toJail)], in.ForceBan...)
	}

	// Expiry only flips bans from active to inactive, so a change in the
	// number of active bans is an exact signal.
	activeBefore := activeBanCount(j)
	j.UpdateBanActiveStatus()
	expired := activeBefore - activeBanCount(j)

	var updateErr error
	if len(toJail) > 0 {
		updateErr = j.Update(toJail)
	}

	// ComposeBanLists is the publish choke point: whitelists win over active
	// bans AND the manual blacklist.
	bans, blacklist := cidr.ComposeBanLists(j.ListActiveBans(), in.Blacklist, in.Whitelist)

	return BanUpdate{
		Bans:             bans,
		Blacklist:        blacklist,
		WhitelistDropped: dropped,
		Jailed:           len(toJail),
		Expired:          expired,
		JailChanged:      len(toJail) > 0 || expired > 0,
		UpdateErr:        updateErr,
	}
}

// activeBanCount counts the running bans without building their list.
func activeBanCount(j *jail.Jail) int {
	n := 0
	for ci := range j.Cells {
		prisoners := j.Cells[ci].Prisoners
		for pi := range prisoners {
			if prisoners[pi].BanActive {
				n++
			}
		}
	}
	return n
}

// publishJailAndBans runs the jail update and ban-file publish step when both a
// jail file and a ban file are configured; otherwise it is a no-op. Shared by
// every successful exit of both static entrypoints (including the empty-log
// exits) so the ban file is refreshed on each run.
//
// Fail loud: a jail/ban processing failure must not exit 0 with no ban file.
// The barrier (Config.Validate) catches an unloadable jail before this; the
// propagation is defense-in-depth for the remaining causes (jail save /
// ban-file write).
func publishJailAndBans(cfg *config.Config, lists *globalLists, jsonOutput *output.JSONOutput) error {
	if cfg.Global == nil || cfg.Global.JailFile == "" || cfg.Global.BanFile == "" {
		return nil
	}
	if err := publishStatic(cfg, lists, jsonOutput); err != nil {
		jsonOutput.AddError("jail_processing", fmt.Sprintf("Failed to process jail with whitelist/blacklist: %v", err), 1)
		return err
	}
	return nil
}

// publishStatic is static mode's side of the ban pipeline: it gathers the
// BanInput from the list files and the analysis results, runs UpdateBans on
// the jail loaded from disk, saves the jail when it changed and rewrites the
// ban file. Each failing stage is recorded in jsonOutput under its own type.
//
// The IP whitelist comes from lists (read once per run); an unreadable one
// fails the publish here, where it matters.
func publishStatic(cfg *config.Config, lists *globalLists, jsonOutput *output.JSONOutput) error {
	if err := lists.whitelistErr; err != nil {
		jsonOutput.AddError("whitelist_load", fmt.Sprintf("Failed to load whitelist: %v", err), 1)
		return err
	}
	blacklistCIDRs, err := cfg.LoadBlacklistCIDRs()
	if err != nil {
		jsonOutput.AddError("blacklist_load", fmt.Sprintf("Failed to load blacklist: %v", err), 1)
		return err
	}

	in := BanInput{
		Detected: jailCandidates(jsonOutput.Tries),
		ForceBan: hostCIDRs(nil, jsonOutput.UserAgentBlacklistIPs),
		// Every whitelist source must win everywhere: before the jail and at
		// the final publish pass.
		Whitelist: hostCIDRs(lists.whitelist, jsonOutput.UserAgentWhitelistIPs),
		Blacklist: blacklistCIDRs,
	}

	jailInstance, err := jail.FileToJail(cfg.GetJailFile())
	if err != nil {
		jsonOutput.AddError("jail_load", fmt.Sprintf("Failed to load jail %q: %v", cfg.GetJailFile(), err), 1)
		return err
	}

	update := UpdateBans(&jailInstance, in)

	if len(in.Whitelist) > 0 && update.WhitelistDropped > 0 {
		jsonOutput.AddWarning("whitelist_applied", fmt.Sprintf("Whitelist filtering prevented %d CIDRs from being added to jail", update.WhitelistDropped), 0)
	}
	if update.UpdateErr != nil {
		jsonOutput.AddWarning("jail_update", fmt.Sprintf("Some CIDRs failed during jail update: %v", update.UpdateErr), 1)
	}

	// Persist when the jail changed: new detections, or bans that just expired.
	if update.JailChanged {
		if err := jail.JailToFile(jailInstance, cfg.GetJailFile()); err != nil {
			jsonOutput.AddError("jail_save", fmt.Sprintf("Failed to save jail %q: %v", cfg.GetJailFile(), err), 1)
			return err
		}
	}

	// The ban file is rewritten on every run.
	if err := jail.WriteBanFileWithBlacklist(cfg.GetBanFile(), update.Bans, update.Blacklist); err != nil {
		jsonOutput.AddError("banfile_write", fmt.Sprintf("Failed to write ban file %q: %v", cfg.GetBanFile(), err), 1)
		return err
	}

	if len(update.Blacklist) > 0 {
		jsonOutput.AddWarning("blacklist_applied", fmt.Sprintf("Added %d manual blacklist entries to ban file", len(update.Blacklist)), 0)
	}

	return nil
}

// jailCandidates collects the merged ranges of every cluster set flagged
// useForJail, in trie order then cluster-set order. Data[i] pairs with
// UseForJail[i] by position (processClustering keeps them aligned).
func jailCandidates(tries []output.TrieResult) []string {
	var cidrs []string
	for _, trieResult := range tries {
		for i, clusterResult := range trieResult.Data {
			if len(trieResult.Parameters.UseForJail) > i && trieResult.Parameters.UseForJail[i] {
				for _, mergedRange := range clusterResult.MergedRanges {
					cidrs = append(cidrs, mergedRange.CIDR)
				}
			}
		}
	}
	return cidrs
}

// hostCIDRs returns a new slice holding cidrs followed by every IP as a /32.
func hostCIDRs(cidrs, ips []string) []string {
	out := make([]string, 0, len(cidrs)+len(ips))
	out = append(out, cidrs...)
	for _, ip := range ips {
		out = append(out, ip+"/32")
	}
	return out
}
