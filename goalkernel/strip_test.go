//go:build pcagoalkernel

package goalkernel

import "fmt"

// stripGoalTape is Strip(g) of the proved compiler (GoalCompile.dfy StripGrants / Strip) on the goal tape: every grant a hole
// depends on (a global hole, or the grant's gid in the hole's affects) is removed and the holes list is emptied. It walks the
// card encoding (GoalRender.dfy EncGoal) only as far as the grants; the holes are the tail of the tape, found by the one keyword
// (k470) that opens a hole and nothing else.
func stripGoalTape(g Tape) (Tape, error) {
	p := &tapeCur{t: g}
	// header: k480, version, principal, ont digest, nl digest, then the sources
	p.skip(5)
	p.strs()
	n := p.count()
	grantStart := p.i
	type span struct {
		gid      string
		from, to int
	}
	var grants []span
	for k := int64(0); k < n && p.err == nil; k++ {
		from := p.i
		p.kw(380)
		gid := p.str()
		p.str()
		p.resSel()
		p.cond()
		grants = append(grants, span{gid, from, p.i})
	}
	if p.err != nil {
		return nil, p.err
	}
	grantsEnd := p.i
	// the holes: [i n] then n holes to the end of the tape
	hj, holes := -1, []hole(nil)
	for j := grantsEnd; j < len(g); j++ {
		if g[j].Tag != 'i' || (g[j].Int == 0) != (j == len(g)-1) {
			continue
		}
		if g[j].Int > 0 && (j+1 >= len(g) || g[j+1].Tag != 'k' || g[j+1].Int != 470) {
			continue
		}
		q := &tapeCur{t: g, i: j}
		hs := q.holes()
		if q.err == nil && q.i == len(g) {
			hj, holes = j, hs
			break
		}
	}
	if hj < 0 {
		return nil, fmt.Errorf("goal tape: no holes section")
	}
	if len(holes) == 0 {
		return g, nil
	}
	depends := func(gid string) bool {
		for _, h := range holes {
			if h.global {
				return true
			}
			for _, a := range h.affects {
				if a == gid {
					return true
				}
			}
		}
		return false
	}
	out := append(Tape{}, g[:grantStart-1]...)
	var kept Tape
	cnt := int64(0)
	for _, s := range grants {
		if !depends(s.gid) {
			kept = append(kept, g[s.from:s.to]...)
			cnt++
		}
	}
	out = append(out, I(cnt))
	out = append(out, kept...)
	out = append(out, g[grantsEnd:hj]...)
	return append(out, I(0)), nil
}

type hole struct {
	affects []string
	global  bool
}

type tapeCur struct {
	t   Tape
	i   int
	err error
}

func (p *tapeCur) fail() {
	if p.err == nil {
		p.err = fmt.Errorf("goal tape: unexpected token at %d", p.i)
	}
}
func (p *tapeCur) peek() Tok {
	if p.i >= len(p.t) {
		p.fail()
		return Tok{}
	}
	return p.t[p.i]
}
func (p *tapeCur) skip(n int) {
	if p.i+n > len(p.t) {
		p.fail()
		return
	}
	p.i += n
}
func (p *tapeCur) kw(k int64) {
	if t := p.peek(); p.err == nil && (t.Tag != 'k' || t.Int != k) {
		p.fail()
		return
	}
	p.i++
}
func (p *tapeCur) kwAny() int64 {
	t := p.peek()
	if p.err != nil || t.Tag != 'k' {
		p.fail()
		return -1
	}
	p.i++
	return t.Int
}
func (p *tapeCur) str() string {
	t := p.peek()
	if p.err != nil || t.Tag != 's' {
		p.fail()
		return ""
	}
	p.i++
	return t.Str
}
func (p *tapeCur) count() int64 {
	t := p.peek()
	if p.err != nil || t.Tag != 'i' || t.Int < 0 || t.Int > int64(len(p.t)) {
		p.fail()
		return 0
	}
	p.i++
	return t.Int
}
func (p *tapeCur) intTok() int64 {
	t := p.peek()
	if p.err != nil || t.Tag != 'i' {
		p.fail()
		return 0
	}
	p.i++
	return t.Int
}
func (p *tapeCur) strs() []string {
	out := []string{}
	for n := p.count(); n > 0 && p.err == nil; n-- {
		out = append(out, p.str())
	}
	return out
}
func (p *tapeCur) unit() {
	switch k := p.kwAny(); k {
	case 300:
		p.str()
	case 301, 302, 303, 304, 305:
	default:
		p.fail()
	}
}
func (p *tapeCur) q() { p.unit(); p.intTok() }
func (p *tapeCur) ty() {
	switch p.kwAny() {
	case 310:
		p.unit()
	case 311:
	default:
		p.fail()
	}
}
func (p *tapeCur) atoms() {
	for n := p.count(); n > 0 && p.err == nil; n-- {
		switch p.kwAny() {
		case 320:
			p.q()
		case 321:
			p.str()
		default:
			p.fail()
		}
	}
}
func (p *tapeCur) val() {
	switch p.kwAny() {
	case 330:
		p.q()
	case 331:
		p.str()
	case 332:
		p.atoms()
	default:
		p.fail()
	}
}
func (p *tapeCur) term() {
	switch p.kwAny() {
	case 340:
		p.str()
		p.ty()
	case 341:
		p.val()
	case 342:
		p.str()
		p.unit()
	default:
		p.fail()
	}
}
func (p *tapeCur) cond() {
	switch k := p.kwAny(); k {
	case 360:
	case 361:
		if op := p.kwAny(); op < 350 || op > 357 {
			p.fail()
		}
		p.term()
		p.term()
	case 362, 363:
		p.cond()
		p.cond()
	case 364:
		p.cond()
	default:
		p.fail()
	}
}
func (p *tapeCur) resSel() {
	switch p.kwAny() {
	case 370:
		p.str()
	case 371:
		p.strs()
	case 372:
		p.str()
		p.str()
	case 373:
		p.str()
	case 374:
		for n := p.count(); n > 0 && p.err == nil; n-- {
			switch p.kwAny() {
			case 375:
				p.str()
			case 376:
				p.strs()
			case 377:
				p.str()
				p.str()
			default:
				p.fail()
			}
		}
	default:
		p.fail()
	}
}
func (p *tapeCur) holes() []hole {
	var out []hole
	for n := p.count(); n > 0 && p.err == nil; n-- {
		p.kw(470)
		p.str()
		p.str()
		p.strs()
		aff := p.strs()
		gl := p.intTok()
		if gl != 0 && gl != 1 {
			p.fail()
		}
		out = append(out, hole{aff, gl == 1})
	}
	return out
}
