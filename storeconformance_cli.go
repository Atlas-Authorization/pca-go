package pca

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

// StoreCliUsage is the usage text of the conformance command.
var StoreCliUsage = `store-conformance --adapter <name|builtin:name> [options]

  --profile pca-state     run the replay store behind the real guard with real signed PCActns (the adapter is then a pca-state adapter:
                          PcaStateRegisterAdapter, or builtin:in-memory | builtin:durable-file | builtin:bad-read-then-write-claim |
                          builtin:bad-volatile | builtin:bad-unshared); --tests then names: ` + strings.Join(PcaStateTests, ", ") + `;
                          --rounds, --clients (copies per round) and --processes apply
  --adapter <name>        a registered adapter (StoreRegisterAdapter) or builtin:in-memory | builtin:durable-file | builtin:bad-* (reference adapters)
  --option k=v            passed to the adapter factory (repeatable)
  --tests a,b             subset of: ` + strings.Join(StoreTests, ", ") + ` (default all)
  --clients N             concurrent clients (default 16)
  --duration MS           concurrent run length (default 2000)
  --rounds N              same-key burst rounds (default 20)
  --revisit-keys N        retention run size (default 500)
  --processes N           crash test: client processes alive at once (default 3)
  --kill-every MS         crash test: kill one client process this often (default 400)
  --budget N              search states per key before it is UNRESOLVED (default 200000)
  --values N              advance tests: counter values are drawn from [0, N) (default 20)
  --seed N                workload PRNG seed, to reproduce a run (default random)
  --json                  print the report as JSON

Exit: 0 pass, 1 violation found, 3 unresolved, 2 usage or adapter error.`

// StoreCliArgs are the parsed command-line arguments.
type StoreCliArgs struct {
	Adapter     string
	Options     map[string]string
	JSON, Help  bool
	Conf        StoreConformanceOptions
	Processes   int
	KillEveryMs float64
	// Profile is "" (the replay / counter store kit) or "pca-state"; PcaStateTests are the --tests of that profile.
	Profile       string
	PcaStateTests []string
}

func storeCliNum(flag string, v []string, i int) (float64, error) {
	if i >= len(v) {
		return 0, fmt.Errorf("%s needs a non-negative number", flag)
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(v[i]), 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
		return 0, fmt.Errorf("%s needs a non-negative number", flag)
	}
	return n, nil
}

// StoreParseCli parses the command line (without the program name).
func StoreParseCli(argv []string) (StoreCliArgs, error) {
	a := StoreCliArgs{Options: map[string]string{}}
	var rawTests []string
	haveTests := false
	for i := 0; i < len(argv); i++ {
		f := argv[i]
		next := func() (string, bool) {
			i++
			if i < len(argv) {
				return argv[i], true
			}
			return "", false
		}
		switch f {
		case "--adapter":
			a.Adapter, _ = next()
		case "--option":
			kv, _ := next()
			eq := strings.Index(kv, "=")
			if eq < 1 {
				return a, errors.New("--option needs k=v")
			}
			a.Options[kv[:eq]] = kv[eq+1:]
		case "--tests":
			v, _ := next()
			haveTests = true
			rawTests = nil
			for _, t := range strings.Split(v, ",") {
				if t != "" {
					rawTests = append(rawTests, t)
				}
			}
		case "--profile":
			p, _ := next()
			if p != "pca-state" {
				return a, fmt.Errorf("--profile: unknown profile %s (known: pca-state)", p)
			}
			a.Profile = p
		case "--json":
			a.JSON = true
		case "-h", "--help":
			a.Help = true
		default:
			var dst func(float64)
			integer := false
			switch f {
			case "--clients":
				dst = func(n float64) { a.Conf.Clients = int(n) }
			case "--duration":
				dst = func(n float64) { a.Conf.DurationMs = n }
			case "--rounds":
				dst = func(n float64) { a.Conf.Rounds = int(n) }
			case "--revisit-keys":
				dst = func(n float64) { a.Conf.RevisitKeys = int(n) }
			case "--processes":
				dst = func(n float64) { a.Processes = int(n) }
			case "--kill-every":
				dst = func(n float64) { a.KillEveryMs = n }
			case "--budget":
				dst = func(n float64) { a.Conf.Budget = int(n) }
			case "--values":
				integer = true
				dst = func(n float64) { a.Conf.Values = int(n) }
			case "--seed":
				integer = true
				dst = func(n float64) { a.Conf.Seed = uint32(n) }
			default:
				return a, fmt.Errorf("unknown argument %s", f)
			}
			n, err := storeCliNum(f, argv, i+1)
			i++
			if err != nil {
				return a, err
			}
			if integer && n != math.Floor(n) {
				if f == "--values" {
					return a, errors.New("--values needs a positive integer")
				}
				return a, errors.New("--seed needs a non-negative integer")
			}
			if f == "--values" && n < 1 {
				return a, errors.New("--values needs a positive integer")
			}
			dst(n)
		}
	}
	if haveTests {
		var bad []string
		knownTests := StoreTests
		if a.Profile == "pca-state" {
			knownTests = PcaStateTests
		}
		for _, t := range rawTests {
			known := false
			for _, k := range knownTests {
				known = known || k == t
			}
			if !known {
				bad = append(bad, t)
			}
		}
		if len(bad) > 0 || len(rawTests) == 0 {
			list := strings.Join(bad, ", ")
			if list == "" {
				list = "(none given)"
			}
			return a, fmt.Errorf("--tests: unknown test(s) %s", list)
		}
		if a.Profile == "pca-state" {
			a.PcaStateTests = rawTests
		} else {
			a.Conf.Tests = rawTests
		}
	}
	return a, nil
}

// StoreWorkerFlag is the hidden first argument with which the command re-runs itself as a crash-test client process.
const StoreWorkerFlag = "--store-conformance-worker"

// StoreCliMain runs the command and returns the exit code: 0 pass, 1 a contract violation was found, 3 unresolved (no violation,
// but not every key could be decided), 2 usage or adapter error. The crash test re-runs this program (StoreWorkerFlag) as its
// client processes, so the program must route its arguments here.
func StoreCliMain(argv []string, out, errOut io.Writer) int {
	if len(argv) > 0 && argv[0] == PcaStateWorkerFlag {
		return pcaStateWorker(argv, errOut)
	}
	if len(argv) == 2 && argv[0] == StoreWorkerFlag {
		var cfg StoreWorkerConfig
		if err := json.Unmarshal([]byte(argv[1]), &cfg); err == nil {
			err = StoreWorkerMain(cfg)
			if err == nil {
				return 0
			}
		}
		fmt.Fprintln(errOut, "store-conformance worker failed")
		return 1
	}
	args, err := StoreParseCli(argv)
	if err != nil {
		fmt.Fprintf(errOut, "%s\n\n%s\n", err.Error(), StoreCliUsage)
		return 2
	}
	if args.Help {
		fmt.Fprintln(out, StoreCliUsage)
		return 0
	}
	if args.Adapter == "" {
		fmt.Fprintf(errOut, "--adapter is required\n\n%s\n", StoreCliUsage)
		return 2
	}
	if args.Profile == "pca-state" {
		return pcaStateCliMain(args, out, errOut)
	}
	adapter, err := StoreLoadAdapter(args.Adapter, args.Options)
	if err != nil {
		fmt.Fprintf(errOut, "cannot load adapter: %s\n", err.Error())
		return 2
	}
	defer func() {
		if td, ok := adapter.(StoreTeardowner); ok {
			_ = td.Teardown()
		}
	}()
	conf := args.Conf
	if exe, err := os.Executable(); err == nil {
		conf.Crash = &StoreCrashOptions{Worker: []string{exe, StoreWorkerFlag}, Adapter: args.Adapter, Options: args.Options, Processes: args.Processes, KillEvery: args.KillEveryMs}
	}
	r, err := RunStoreConformance(adapter, conf)
	if err != nil {
		fmt.Fprintf(errOut, "conformance run failed: %s\n", err.Error())
		return 2
	}
	if args.JSON {
		fmt.Fprintln(out, StoreReportJSON(r))
	} else {
		fmt.Fprintln(out, StoreFormatReport(r, 3))
	}
	switch r.Status {
	case "pass":
		return 0
	case "fail":
		return 1
	}
	return 3
}
