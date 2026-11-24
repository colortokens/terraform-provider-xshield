package provider

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

const (
	azureLowestRulePriority  = 100
	azureHighestRulePriority = 4096
)

var azureDirections = []string{"Inbound", "Outbound"}

// azurePriorityHolder is a rule as far as Azure's one-rule-per-priority-and-direction limit sees it.
type azurePriorityHolder struct {
	name      string
	direction string
	priority  int64
}

func isXshieldRuleName(name string) bool {
	return strings.HasPrefix(name, "CT-Rule-") || strings.HasPrefix(name, "CT-Test-Rule-")
}

// numberAheadOfYours gives Xshield's rules for a group of yours priorities below every rule of yours, so Azure evaluates
// them first. A rule the group already holds keeps its priority while that still keeps the order, and any other rule
// takes a priority no rule in the group holds now, so applying the rules one at a time never puts two at one priority.
func numberAheadOfYours(groupName string, wanted []wireAzureSecurityRule, yours, current []azurePriorityHolder) ([]wireAzureSecurityRule, error) {
	numbered := []wireAzureSecurityRule{}
	for _, direction := range azureDirections {
		rules := slices.DeleteFunc(slices.Clone(wanted), func(r wireAzureSecurityRule) bool { return !strings.EqualFold(r.Direction, direction) })
		if len(rules) == 0 {
			continue
		}
		room := azureRoomOf(direction, slices.Concat(yours, current))
		runs := sameAccessRuns(rules)
		inOrder, fits := room.number(runs, true)
		if !fits {
			inOrder, fits = room.number(runs, false)
		}
		if !fits {
			return nil, room.tooFullError(groupName, direction, len(rules))
		}
		numbered = append(numbered, inOrder...)
	}
	return numbered, nil
}

// azureRoom is what one direction of a group leaves Xshield: the priorities below ceiling that no rule holds, and the
// priorities its rules hold now.
type azureRoom struct {
	ceiling  int64
	occupied map[int64]bool
	held     map[string]int64
}

func azureRoomOf(direction string, holders []azurePriorityHolder) azureRoom {
	room := azureRoom{ceiling: azureHighestRulePriority + 1, occupied: map[int64]bool{}, held: map[string]int64{}}
	for _, h := range holders {
		if !strings.EqualFold(h.direction, direction) {
			continue
		}
		room.occupied[h.priority] = true
		if isXshieldRuleName(h.name) {
			room.held[h.name] = h.priority
			continue
		}
		room.ceiling = min(room.ceiling, h.priority)
	}
	return room
}

func (room azureRoom) tooFullError(groupName, direction string, rules int) error {
	direction = strings.ToLower(direction)
	if room.ceiling > azureHighestRulePriority {
		return fmt.Errorf("network security group %s has no room for Xshield's %d %s rules: Azure allows priorities %d to %d, and its rules hold too many of them",
			groupName, rules, direction, azureLowestRulePriority, azureHighestRulePriority)
	}
	return fmt.Errorf("network security group %s has no room for Xshield's %d %s rules ahead of yours: Azure numbers rules from %d, and your "+
		"first %s rule is at priority %d. Move your %s rules up to leave at least %d priorities below your first one that no rule holds",
		groupName, rules, direction, azureLowestRulePriority, direction, room.ceiling, direction, rules)
}

// number places each run above the one before it. Inside a run every rule has the same access, so their order decides
// nothing and a held priority anywhere above the earlier runs keeps the run's meaning.
func (room azureRoom) number(runs [][]wireAzureSecurityRule, keepHeld bool) ([]wireAzureSecurityRule, bool) {
	taken := map[int64]bool{}
	floor := int64(azureLowestRulePriority - 1)
	out := []wireAzureSecurityRule{}
	for _, run := range runs {
		top := floor
		unplaced := []wireAzureSecurityRule{}
		for _, r := range run {
			p, held := room.held[r.Name]
			if !keepHeld || !held || p <= floor || p >= room.ceiling || taken[p] {
				unplaced = append(unplaced, r)
				continue
			}
			r.Priority, taken[p], top = p, true, max(top, p)
			out = append(out, r)
		}
		next := floor + 1
		for _, r := range unplaced {
			for next < room.ceiling && (room.occupied[next] || taken[next]) {
				next++
			}
			if next >= room.ceiling {
				return nil, false
			}
			r.Priority, taken[next], top = next, true, max(top, next)
			out = append(out, r)
		}
		floor = top
	}
	return out, true
}

// sameAccessRuns splits rules, in the order their snapshot priorities give, wherever the access changes.
func sameAccessRuns(rules []wireAzureSecurityRule) [][]wireAzureSecurityRule {
	slices.SortStableFunc(rules, func(a, b wireAzureSecurityRule) int { return cmp.Compare(a.Priority, b.Priority) })
	runs := [][]wireAzureSecurityRule{}
	for i, r := range rules {
		if i == 0 || !strings.EqualFold(r.Access, rules[i-1].Access) {
			runs = append(runs, nil)
		}
		runs[len(runs)-1] = append(runs[len(runs)-1], r)
	}
	return runs
}
