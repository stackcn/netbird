package peer

import (
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
)

const (
	defaultNATPredictionMinSamples      = 3
	defaultNATPredictionMaxStep         = 16
	defaultNATPredictionForwardWindow   = 12
	defaultNATPredictionBackwardWindow  = 2
	defaultNATPredictionMaxCandidates   = 16
	natPredictionSampleTTL               = 30 * time.Second
	predictedCandidatePriorityPenalty   = uint32(2000)
)

type natPredictionConfig struct {
	enabled        bool
	minSamples     int
	maxStep        int
	forwardWindow  int
	backwardWindow int
	maxCandidates  int
}

type natPredictionState struct {
	mu sync.Mutex

	sessionID string
	publicIP  string
	ports     []int
	seenPorts map[int]struct{}
	generated map[int]struct{}
	lastSeen  time.Time
}

var natPredictionStates sync.Map // map[*WorkerICE]*natPredictionState

func loadNATPredictionConfig() natPredictionConfig {
	return natPredictionConfig{
		enabled:        envBool("NB_NAT_PORT_PREDICTION", false),
		minSamples:     envInt("NB_NAT_PORT_PREDICTION_MIN_SAMPLES", defaultNATPredictionMinSamples, 3, 16),
		maxStep:        envInt("NB_NAT_PORT_PREDICTION_MAX_STEP", defaultNATPredictionMaxStep, 1, 256),
		forwardWindow:  envInt("NB_NAT_PORT_PREDICTION_FORWARD_WINDOW", defaultNATPredictionForwardWindow, 1, 64),
		backwardWindow: envInt("NB_NAT_PORT_PREDICTION_BACKWARD_WINDOW", defaultNATPredictionBackwardWindow, 0, 16),
		maxCandidates:  envInt("NB_NAT_PORT_PREDICTION_MAX_CANDIDATES", defaultNATPredictionMaxCandidates, 1, 64),
	}
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(name string, fallback, minValue, maxValue int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	if parsed < minValue {
		return minValue
	}
	if parsed > maxValue {
		return maxValue
	}
	return parsed
}

// observeNATPortPrediction records server-reflexive mappings produced by the same
// ICE worker. When the public IPv4 stays the same and the last N mappings show a
// stable, small non-zero port delta, it signals a bounded set of predicted
// server-reflexive candidates to the remote peer. The remote ICE agent then
// performs normal connectivity checks against those candidates. A successful
// packet is learned by ICE as the actual path (often as a peer-reflexive path).
//
// This is deliberately opt-in because it increases connectivity checks and is
// only useful for endpoint-dependent NATs with predictable port allocation.
func (w *WorkerICE) observeNATPortPrediction(candidate ice.Candidate) {
	cfg := loadNATPredictionConfig()
	if !cfg.enabled || candidate == nil || candidate.Type() != ice.CandidateTypeServerReflexive {
		return
	}

	ip := net.ParseIP(candidate.Address())
	if ip == nil || ip.To4() == nil {
		return
	}

	port := candidate.Port()
	if port <= 0 || port > 65535 {
		return
	}

	sessionID := w.SessionID().String()
	now := time.Now()

	stateAny, _ := natPredictionStates.LoadOrStore(w, &natPredictionState{})
	state := stateAny.(*natPredictionState)

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.sessionID != sessionID || state.publicIP != candidate.Address() || now.Sub(state.lastSeen) > natPredictionSampleTTL {
		state.sessionID = sessionID
		state.publicIP = candidate.Address()
		state.ports = nil
		state.seenPorts = make(map[int]struct{})
		state.generated = make(map[int]struct{})
	}
	state.lastSeen = now

	if _, exists := state.seenPorts[port]; exists {
		return
	}
	state.seenPorts[port] = struct{}{}
	state.ports = append(state.ports, port)

	// Retain a bounded recent history so a long-lived worker cannot grow without bound.
	maxHistory := cfg.minSamples + 8
	if len(state.ports) > maxHistory {
		old := state.ports[0]
		state.ports = state.ports[len(state.ports)-maxHistory:]
		delete(state.seenPorts, old)
	}

	w.log.Infof("NAT port prediction sample: public=%s:%d samples=%v", candidate.Address(), port, append([]int(nil), state.ports...))

	step, ok := detectStableNATPortStep(state.ports, cfg.minSamples, cfg.maxStep)
	if !ok {
		return
	}

	predictedPorts := buildPredictedPortWindow(port, step, cfg)
	if len(predictedPorts) == 0 {
		return
	}

	w.log.Infof("NAT port prediction detected sequential mapping: public=%s step=%+d last=%d candidates=%v", candidate.Address(), step, port, predictedPorts)

	for _, predictedPort := range predictedPorts {
		if _, exists := state.seenPorts[predictedPort]; exists {
			continue
		}
		if _, exists := state.generated[predictedPort]; exists {
			continue
		}

		predictedCandidate, err := createPredictedSrflxCandidate(candidate, predictedPort)
		if err != nil {
			w.log.Debugf("NAT port prediction: failed creating candidate %s:%d: %v", candidate.Address(), predictedPort, err)
			continue
		}
		state.generated[predictedPort] = struct{}{}

		w.log.Infof("NAT port prediction signaling candidate: %s:%d priority=%d", candidate.Address(), predictedPort, predictedCandidate.Priority())
		go func(c ice.Candidate) {
			if err := w.signaler.SignalICECandidate(c, w.config.Key); err != nil {
				w.log.Errorf("NAT port prediction: failed signaling candidate to peer %s: %v", w.config.Key, err)
			}
		}(predictedCandidate)
	}
}

func detectStableNATPortStep(ports []int, minSamples, maxStep int) (int, bool) {
	if len(ports) < minSamples {
		return 0, false
	}

	window := ports[len(ports)-minSamples:]
	step := window[1] - window[0]
	if step == 0 || absInt(step) > maxStep {
		return 0, false
	}

	for i := 2; i < len(window); i++ {
		if window[i]-window[i-1] != step {
			return 0, false
		}
	}
	return step, true
}

func buildPredictedPortWindow(lastPort, step int, cfg natPredictionConfig) []int {
	primary := lastPort + step
	candidates := make(map[int]struct{})

	// Center the scan around the predicted next allocation. The window is in
	// absolute ports (not multiples of step) because another flow may consume one
	// or more allocations between STUN sampling and the real peer check.
	for delta := -cfg.backwardWindow; delta <= cfg.forwardWindow; delta++ {
		port := primary + delta
		if port <= 0 || port > 65535 {
			continue
		}
		candidates[port] = struct{}{}
	}

	ports := make([]int, 0, len(candidates))
	for port := range candidates {
		ports = append(ports, port)
	}

	// Prefer ports closest to the predicted next port; use the numeric port only
	// as a deterministic tie breaker.
	sort.Slice(ports, func(i, j int) bool {
		di := absInt(ports[i] - primary)
		dj := absInt(ports[j] - primary)
		if di == dj {
			return ports[i] < ports[j]
		}
		return di < dj
	})

	if len(ports) > cfg.maxCandidates {
		ports = ports[:cfg.maxCandidates]
	}
	return ports
}

func createPredictedSrflxCandidate(base ice.Candidate, port int) (ice.Candidate, error) {
	related := base.RelatedAddress()
	relAddr := related.Address
	relPort := related.Port
	if relAddr == "" || relAddr == "0.0.0.0" || relAddr == "::" {
		relAddr = base.Address()
	}

	priority := base.Priority()
	if priority > predictedCandidatePriorityPenalty {
		priority -= predictedCandidatePriorityPenalty
	}

	candidate, err := ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
		Network:   base.NetworkType().String(),
		Address:   base.Address(),
		Port:      port,
		Component: base.Component(),
		Priority:  priority,
		RelAddr:   relAddr,
		RelPort:   relPort,
	})
	if err != nil {
		return nil, err
	}

	// Preserve extensions that are safe to copy. Candidate ID must remain unique
	// for each predicted address/port, so do not copy the source candidate ID.
	for _, extension := range base.Extensions() {
		if extension.Key == ice.ExtensionKeyCandidateID {
			continue
		}
		if err := candidate.AddExtension(extension); err != nil {
			return nil, err
		}
	}

	return candidate, nil
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
