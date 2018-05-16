package ip2service

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	natTable        = "nat"
	preroutingChain = "PREROUTING"
	prefixTarget    = "-TARGET-"
	prefixRelay     = "-RELAY-"

	maxChainNameLength = 28
)

var (
	hashSep = []byte{0}
)

type IPTables interface {
	NewChain(table, chain string) error
	ListChains(table string) ([]string, error)
	Insert(table, chain string, pos int, rulespec ...string) error
	Append(table, chain string, rulespec ...string) error
	AppendUnique(table, chain string, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	ClearChain(table, chain string) error
	DeleteChain(table, chain string) error
}

type Router struct {
	Logger        *zap.Logger
	Prefix        string
	InterceptIP   string
	InterceptPort int32
	IPTables      IPTables
}

func (r *Router) EnsureRoute(targetPort int32, ips []string) error {
	existingChains, err := r.IPTables.ListChains(natTable)
	if err != nil {
		return errors.Wrapf(err, "failed to list chains in table %q", natTable)
	}

	targetPortStr := strconv.Itoa(int(targetPort))
	interceptPortStr := strconv.Itoa(int(r.InterceptPort))
	// Construct target chain
	targetChainNameParts := make([]string, 0, len(ips)+1)
	targetChainNameParts = append(targetChainNameParts, ips...)
	sort.Strings(targetChainNameParts)
	targetChainNameParts = append(targetChainNameParts, targetPortStr)
	targetChainName := r.chainName(prefixTarget, targetChainNameParts...)
	targetChainAlreadyExisted, err := r.createUniqueChain(existingChains, natTable, targetChainName)
	if err != nil {
		return errors.Wrapf(err, "failed to create target chain %q in table %q", targetChainName, natTable)
	}
	if !targetChainAlreadyExisted {
		// Populate chain if it was just created
		n := len(ips)
		if n == 0 {
			// TODO add a drop rule here
			//err = r.IPTables.Append(natTable, targetChainName, "-p", "tcp",
			//	"-m", "comment", "--comment", "Target chain",
			//	"-j", "DROP")
		} else {
			for i, ip := range ips {
				ruleSpec := []string{
					"-p", "tcp",
					"-m", "comment", "--comment", "Target chain",
				}
				if i < n-1 {
					ruleSpec = append(ruleSpec, "-m", "statistic", "--mode", "random", "--probability", computeProbability(n-i))
				}
				ruleSpec = append(ruleSpec, "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", ip, targetPort))

				err = r.IPTables.Append(natTable, targetChainName, ruleSpec...)
				if err != nil {
					return errors.Wrapf(err, "failed append to target chain %q in table %q", targetChainName, natTable)
				}
			}
		}
	}

	// Construct relay chain
	relayChainName := r.chainName(prefixRelay, r.InterceptIP, interceptPortStr)
	_, err = r.createUniqueChain(existingChains, natTable, relayChainName)
	if err != nil {
		return errors.Wrapf(err, "failed to create relay chain %q in table %q", relayChainName, natTable)
	}
	err = r.IPTables.Insert(
		natTable, relayChainName, 1,
		"-m", "comment", "--comment", "Relay chain",
		"-j", targetChainName)
	if err != nil {
		return errors.Wrapf(err, "failed to insert a rule into relay chain %q in table %q", relayChainName, natTable)
	}

	// Forward to relay chain
	err = r.IPTables.AppendUnique(
		natTable, preroutingChain, "-p", "tcp", "-d", r.InterceptIP, "--dport", interceptPortStr,
		"-m", "comment", "--comment", fmt.Sprintf("Forward to relay for %s:%d", r.InterceptIP, r.InterceptPort),
		"-j", relayChainName)
	if err != nil {
		return err
	}

	// Garbage collection
	// Drop all other existing target chains and their usages in relay chain
	for _, chain := range existingChains {
		if chain == targetChainName || !strings.HasPrefix(chain, r.Prefix+prefixTarget) {
			// Current target chain or a non-target chain
			continue
		}
		// Old target chain
		// Remove rules from relay chain
		err = r.IPTables.Delete(natTable, relayChainName, "-j", chain)
		if err != nil {
			r.Logger.With(zap.Error(err)).Sugar().Errorf(
				"Failed to delete a rule for chain %q from relay chain %q in table %q",
				chain, relayChainName, natTable)
			continue
		}
		err = r.IPTables.ClearChain(natTable, chain)
		if err != nil {
			r.Logger.With(zap.Error(err)).Sugar().Errorf("Failed to clear chain %q in table %q", chain, natTable)
			continue
		}
		err = r.IPTables.DeleteChain(natTable, chain)
		if err != nil {
			r.Logger.With(zap.Error(err)).Sugar().Errorf("Failed to delete chain %q in table %q", chain, natTable)
		}
	}

	return nil
}

func (r *Router) chainName(prefix string, parts ...string) string {
	return (r.Prefix + prefix + hash(parts...))[:maxChainNameLength]
}

func (r *Router) createUniqueChain(existingChains []string, table, chain string) (bool /* already existed */, error) {
	for _, existingChain := range existingChains {
		if existingChain == chain {
			// Chain already exists
			return true, nil
		}
	}
	// Not found, need to create
	err := r.IPTables.NewChain(table, chain)
	if err != nil {
		return false, errors.Wrap(err, "failed to create chain in table")
	}
	return false, nil
}

func computeProbability(n int) string {
	return fmt.Sprintf("%0.5f", 1.0/float64(n))
}

func hash(parts ...string) string {
	s := sha256.New()
	for _, part := range parts {
		// Use a separator byte to reduce the chance of a collision
		s.Write([]byte(part))
		s.Write(hashSep)
	}
	h := s.Sum(nil)
	return base32.StdEncoding.EncodeToString(h)
}
