package pca

import "errors"

// A multi-agent session, the delegation-tree "team" view: a root agent plus the sub-agents it delegates to all share ONE signed goal;
// the session groups them so a principal sees the whole team under a goal and the console can be scoped to it. Pure.

// SessionMaxDepth is the deepest delegation chain a session accepts.
const SessionMaxDepth = 32

// Session is a root agent and the sub-agents delegated under it.
type Session struct {
	// Root is the first agent of the session.
	Root *FacadeAgent
	// Members is the root first, then each added sub-agent, in delegation order.
	Members []*FacadeAgent
	// GoalCommit is the shared signed goal commitment (from the root grant), "" when the grant carries none.
	GoalCommit string
}

func sessionGoalOf(h *FacadeAgent) string {
	if env := ReadEnvelope(h.Grant); env != nil {
		if s, ok := env["goal_commit"].(string); ok {
			return s
		}
	}
	return ""
}

// StartSession starts a session from a root agent.
func StartSession(root *FacadeAgent) *Session {
	return &Session{Root: root, Members: []*FacadeAgent{root}, GoalCommit: sessionGoalOf(root)}
}

// AddMember adds a sub-agent: one attenuated delegation hop under the session's current leaf. child (the sub-agent's key) and
// addedCaveats may be nil. It errors past SessionMaxDepth hops. The grown session and the new member are returned.
func AddMember(s *Session, child *KeyPair, addedCaveats []any) (*Session, *FacadeAgent, error) {
	if len(s.Members) > SessionMaxDepth {
		return nil, nil, errors.New("addMember: a session is limited to 32 delegation hops")
	}
	if len(s.Members) == 0 {
		return nil, nil, errors.New("addMember: a session has no members")
	}
	member, err := s.Members[len(s.Members)-1].SubAgent(SubAgentOptions{Holder: child, AddedCaveats: addedCaveats})
	if err != nil {
		return nil, nil, err
	}
	next := append(append([]*FacadeAgent(nil), s.Members...), member)
	return &Session{Root: s.Root, Members: next, GoalCommit: s.GoalCommit}, member, nil
}

// SessionAgents are the holder ids (b64u public keys) of every agent in the session.
func SessionAgents(s *Session) []string {
	out := make([]string, 0, len(s.Members))
	for _, m := range s.Members {
		out = append(out, m.Holder.Public)
	}
	return out
}

// SessionConsole is a console view scoped to just this session's agents.
func SessionConsole(s *Session, events []any) (map[string]any, error) {
	ids := map[string]bool{}
	for _, id := range SessionAgents(s) {
		ids[id] = true
	}
	mine := []any{}
	for _, e := range events {
		if e == nil {
			return nil, errors.New("sessionConsole: an event must not be null")
		}
		if m := rsMap(e); m != nil {
			if a, ok := m["agent"].(string); ok && ids[a] {
				mine = append(mine, e)
			}
		}
	}
	return BuildConsole(mine)
}

// SharesGoal is true iff every member shares the root's goal commitment (a well-formed team). A root without a readable envelope has no
// goal commitment (""), and members that all lack one do not "share a goal": false.
func SharesGoal(s *Session) bool {
	if s.GoalCommit == "" {
		return false
	}
	for _, m := range s.Members {
		if sessionGoalOf(m) != s.GoalCommit {
			return false
		}
	}
	return true
}

// SessionDepth is the depth of the delegation tree (0 = root only).
func SessionDepth(s *Session) int { return len(s.Members) - 1 }
