// Package GoalCompile
// Dafny module GoalCompile compiled into Go

package GoalCompile

import (
	m_GoalIr "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/GoalIr"
	m__System "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/System_"
	_dafny "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/dafny"
	os "os"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__
var _ m_GoalIr.Dummy__

type Dummy__ struct{}

// Definition of class Default__
type Default__ struct {
	dummy byte
}

func New_Default___() *Default__ {
	_this := Default__{}

	return &_this
}

type CompanionStruct_Default___ struct {
}

var Companion_Default___ = CompanionStruct_Default___{}

func (_this *Default__) Equals(other *Default__) bool {
	return _this == other
}

func (_this *Default__) EqualsGeneric(x interface{}) bool {
	other, ok := x.(*Default__)
	return ok && _this.Equals(other)
}

func (*Default__) String() string {
	return "GoalCompile.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) EvalN(c NC, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	var _source0 NC = c
	_ = _source0
	{
		if _source0.Is_NTrue() {
			return m_GoalIr.Companion_Default___.KT()
		}
	}
	{
		if _source0.Is_NFalse() {
			return m_GoalIr.Companion_Default___.KF()
		}
	}
	{
		if _source0.Is_NAtom() {
			var _0_op m_GoalIr.Op = _source0.Get_().(NC_NAtom).Op
			_ = _0_op
			var _1_l m_GoalIr.Term = _source0.Get_().(NC_NAtom).L
			_ = _1_l
			var _2_r m_GoalIr.Term = _source0.Get_().(NC_NAtom).R
			_ = _2_r
			return m_GoalIr.Companion_Default___.CmpT(_0_op, m_GoalIr.Companion_Default___.EvalT(_1_l, a, h), m_GoalIr.Companion_Default___.EvalT(_2_r, a, h))
		}
	}
	{
		if _source0.Is_NAnd() {
			var _3_x NC = _source0.Get_().(NC_NAnd).A
			_ = _3_x
			var _4_y NC = _source0.Get_().(NC_NAnd).B
			_ = _4_y
			return m_GoalIr.Companion_Default___.AndK(Companion_Default___.EvalN(_3_x, a, h), Companion_Default___.EvalN(_4_y, a, h))
		}
	}
	{
		var _5_x NC = _source0.Get_().(NC_NOr).A
		_ = _5_x
		var _6_y NC = _source0.Get_().(NC_NOr).B
		_ = _6_y
		return m_GoalIr.Companion_Default___.OrK(Companion_Default___.EvalN(_5_x, a, h), Companion_Default___.EvalN(_6_y, a, h))
	}
}
func (_static *CompanionStruct_Default___) Nnf(c m_GoalIr.Cond, pos bool) NC {
	var _source0 m_GoalIr.Cond = c
	_ = _source0
	{
		if _source0.Is_CTrue() {
			if pos {
				return Companion_NC_.Create_NTrue_()
			} else {
				return Companion_NC_.Create_NFalse_()
			}
		}
	}
	{
		if _source0.Is_Cmp() {
			var _0_op m_GoalIr.Op = _source0.Get_().(m_GoalIr.Cond_Cmp).Op
			_ = _0_op
			var _1_l m_GoalIr.Term = _source0.Get_().(m_GoalIr.Cond_Cmp).L
			_ = _1_l
			var _2_r m_GoalIr.Term = _source0.Get_().(m_GoalIr.Cond_Cmp).R
			_ = _2_r
			return Companion_NC_.Create_NAtom_((func() m_GoalIr.Op {
				if pos {
					return _0_op
				}
				return m_GoalIr.Companion_Default___.NegOp(_0_op)
			})(), _1_l, _2_r)
		}
	}
	{
		if _source0.Is_And() {
			var _3_x m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_And).A
			_ = _3_x
			var _4_y m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_And).B
			_ = _4_y
			if pos {
				return Companion_NC_.Create_NAnd_(Companion_Default___.Nnf(_3_x, true), Companion_Default___.Nnf(_4_y, true))
			} else {
				return Companion_NC_.Create_NOr_(Companion_Default___.Nnf(_3_x, false), Companion_Default___.Nnf(_4_y, false))
			}
		}
	}
	{
		if _source0.Is_Or() {
			var _5_x m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_Or).A
			_ = _5_x
			var _6_y m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_Or).B
			_ = _6_y
			if pos {
				return Companion_NC_.Create_NOr_(Companion_Default___.Nnf(_5_x, true), Companion_Default___.Nnf(_6_y, true))
			} else {
				return Companion_NC_.Create_NAnd_(Companion_Default___.Nnf(_5_x, false), Companion_Default___.Nnf(_6_y, false))
			}
		}
	}
	{
		var _7_x m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_Not).C
		_ = _7_x
		return Companion_Default___.Nnf(_7_x, !(pos))
	}
}
func (_static *CompanionStruct_Default___) ProhOneP(p LProh, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	var _0_m _dafny.Int = m_GoalIr.Companion_Default___.AndK(m_GoalIr.Companion_Default___.B2T(_dafny.Companion_Sequence_.Contains((p).Dtor_verbs(), (a).Dtor_verb())), m_GoalIr.Companion_Default___.AndK(m_GoalIr.Companion_Default___.B2T(m_GoalIr.Companion_Default___.ResOk((p).Dtor_res(), (a).Dtor_res())), Companion_Default___.EvalN((p).Dtor_cond(), a, h)))
	_ = _0_m
	if (_0_m).Cmp(m_GoalIr.Companion_Default___.KT()) == 0 {
		return m_GoalIr.Companion_Default___.Deny()
	} else if (_0_m).Cmp(m_GoalIr.Companion_Default___.KU()) == 0 {
		return m_GoalIr.Companion_Default___.Escalate()
	} else {
		return m_GoalIr.Companion_Default___.Allow()
	}
}
func (_static *CompanionStruct_Default___) ProhDecP(ps _dafny.Sequence, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	if (_dafny.IntOfUint32((ps).Cardinality())).Sign() == 0 {
		return m_GoalIr.Companion_Default___.Allow()
	} else {
		return m_GoalIr.Companion_Default___.MeetD(Companion_Default___.ProhOneP((ps).Select(0).(LProh), a, h), Companion_Default___.ProhDecP((ps).Drop(1), a, h))
	}
}
func (_static *CompanionStruct_Default___) EscDecP(cs _dafny.Sequence, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	if (_dafny.IntOfUint32((cs).Cardinality())).Sign() == 0 {
		return m_GoalIr.Companion_Default___.Allow()
	} else {
		return m_GoalIr.Companion_Default___.MeetD(m_GoalIr.Companion_Default___.EscOne(Companion_Default___.EvalN((cs).Select(0).(NC), a, h)), Companion_Default___.EscDecP((cs).Drop(1), a, h))
	}
}
func (_static *CompanionStruct_Default___) CeilOne(c LCeil, gid _dafny.Sequence, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	if m_GoalIr.Companion_Default___.AppliesL((c).Dtor_sel(), gid, (a).Dtor_verb()) {
		return m_GoalIr.Companion_Default___.BoundStat((c).Dtor_core(), (c).Dtor_sel(), a, h)
	} else {
		return m_GoalIr.Companion_Default___.Allow()
	}
}
func (_static *CompanionStruct_Default___) CeilsDecP(cs _dafny.Sequence, gid _dafny.Sequence, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	if (_dafny.IntOfUint32((cs).Cardinality())).Sign() == 0 {
		return m_GoalIr.Companion_Default___.Allow()
	} else {
		return m_GoalIr.Companion_Default___.MeetD(Companion_Default___.CeilOne((cs).Select(0).(LCeil), gid, a, h), Companion_Default___.CeilsDecP((cs).Drop(1), gid, a, h))
	}
}
func (_static *CompanionStruct_Default___) PredMatch(p LPred, dg m_GoalIr.Delegation, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	return m_GoalIr.Companion_Default___.AndK(m_GoalIr.Companion_Default___.B2T((_dafny.Companion_Sequence_.Equal((a).Dtor_verb(), (p).Dtor_verb())) && (m_GoalIr.Companion_Default___.DelegOk(dg, (p).Dtor_gid(), a))), m_GoalIr.Companion_Default___.AndK(m_GoalIr.Companion_Default___.B2T(m_GoalIr.Companion_Default___.ResOk((p).Dtor_res(), (a).Dtor_res())), Companion_Default___.EvalN((p).Dtor_cond(), a, h)))
}
func (_static *CompanionStruct_Default___) PredDec(p LPred, ceils _dafny.Sequence, dg m_GoalIr.Delegation, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	return m_GoalIr.Companion_Default___.MeetD(m_GoalIr.Companion_Default___.DecOfTri(Companion_Default___.PredMatch(p, dg, a, h)), Companion_Default___.CeilsDecP(ceils, (p).Dtor_gid(), a, h))
}
func (_static *CompanionStruct_Default___) PredsDecP(ps _dafny.Sequence, ceils _dafny.Sequence, dg m_GoalIr.Delegation, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	if (_dafny.IntOfUint32((ps).Cardinality())).Sign() == 0 {
		return m_GoalIr.Companion_Default___.Deny()
	} else {
		return m_GoalIr.Companion_Default___.JoinD(Companion_Default___.PredDec((ps).Select(0).(LPred), ceils, dg, a, h), Companion_Default___.PredsDecP((ps).Drop(1), ceils, dg, a, h))
	}
}
func (_static *CompanionStruct_Default___) DP(p Pol, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	return m_GoalIr.Companion_Default___.MeetD(m_GoalIr.Companion_Default___.ValidityDec((p).Dtor_validity(), (p).Dtor_deleg(), a, h), m_GoalIr.Companion_Default___.MeetD(Companion_Default___.ProhDecP((p).Dtor_prohs(), a, h), m_GoalIr.Companion_Default___.MeetD(Companion_Default___.EscDecP((p).Dtor_escs(), a, h), Companion_Default___.PredsDecP((p).Dtor_preds(), (p).Dtor_ceils(), (p).Dtor_deleg(), a, h))))
}
func (_static *CompanionStruct_Default___) LowerGrants(ont m_GoalIr.Ontology, gs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((gs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf(Companion_LPred_.Create_LPred_(((gs).Select(0).(m_GoalIr.Grant)).Dtor_gid(), ((gs).Select(0).(m_GoalIr.Grant)).Dtor_verb(), m_GoalIr.Companion_Default___.ResolveSel(ont, ((gs).Select(0).(m_GoalIr.Grant)).Dtor_res()), Companion_Default___.Nnf(((gs).Select(0).(m_GoalIr.Grant)).Dtor_cond(), true))))
		var _in0 m_GoalIr.Ontology = ont
		_ = _in0
		var _in1 _dafny.Sequence = (gs).Drop(1)
		_ = _in1
		ont = _in0
		gs = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) LowerProhs(ont m_GoalIr.Ontology, ps _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((ps).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf(Companion_LProh_.Create_LProh_(((ps).Select(0).(m_GoalIr.Prohibit)).Dtor_pid(), m_GoalIr.Companion_Default___.ProhVerbs(ont, ((ps).Select(0).(m_GoalIr.Prohibit)).Dtor_target()), m_GoalIr.Companion_Default___.ResolveSel(ont, ((ps).Select(0).(m_GoalIr.Prohibit)).Dtor_res()), Companion_Default___.Nnf(((ps).Select(0).(m_GoalIr.Prohibit)).Dtor_cond(), true))))
		var _in0 m_GoalIr.Ontology = ont
		_ = _in0
		var _in1 _dafny.Sequence = (ps).Drop(1)
		_ = _in1
		ont = _in0
		ps = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) LowerBounds(ont m_GoalIr.Ontology, bs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((bs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf(Companion_LCeil_.Create_LCeil_(((bs).Select(0).(m_GoalIr.Bound)).Dtor_bid(), m_GoalIr.Companion_Default___.ResolveBSel(ont, ((bs).Select(0).(m_GoalIr.Bound)).Dtor_sel()), ((bs).Select(0).(m_GoalIr.Bound)).Dtor_core())))
		var _in0 m_GoalIr.Ontology = ont
		_ = _in0
		var _in1 _dafny.Sequence = (bs).Drop(1)
		_ = _in1
		ont = _in0
		bs = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) LowerEscs(cs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((cs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf(Companion_Default___.Nnf((cs).Select(0).(m_GoalIr.Cond), true)))
		var _in0 _dafny.Sequence = (cs).Drop(1)
		_ = _in0
		cs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) Lower(ont m_GoalIr.Ontology, g m_GoalIr.Goal) Pol {
	return Companion_Pol_.Create_Pol_(Companion_Default___.LowerGrants(ont, (g).Dtor_grants()), Companion_Default___.LowerProhs(ont, (g).Dtor_prohibits()), Companion_Default___.LowerBounds(ont, (g).Dtor_bounds()), Companion_Default___.LowerEscs((g).Dtor_escalateOn()), (g).Dtor_validity(), (g).Dtor_deleg())
}
func (_static *CompanionStruct_Default___) DependsOn(hs _dafny.Sequence, gid _dafny.Sequence) bool {
	return ((_dafny.IntOfUint32((hs).Cardinality())).Sign() == 1) && (((((hs).Select(0).(m_GoalIr.Hole)).Dtor_global()) || (_dafny.Companion_Sequence_.Contains(((hs).Select(0).(m_GoalIr.Hole)).Dtor_affects(), gid))) || (Companion_Default___.DependsOn((hs).Drop(1), gid)))
}
func (_static *CompanionStruct_Default___) StripGrants(hs _dafny.Sequence, gs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((gs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if Companion_Default___.DependsOn(hs, ((gs).Select(0).(m_GoalIr.Grant)).Dtor_gid()) {
				return _dafny.SeqOf()
			}
			return _dafny.SeqOf((gs).Select(0).(m_GoalIr.Grant))
		})())
		var _in0 _dafny.Sequence = hs
		_ = _in0
		var _in1 _dafny.Sequence = (gs).Drop(1)
		_ = _in1
		hs = _in0
		gs = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) Strip(g m_GoalIr.Goal) m_GoalIr.Goal {
	var _0_dt__update__tmp_h0 m_GoalIr.Goal = g
	_ = _0_dt__update__tmp_h0
	var _1_dt__update_hholes_h0 _dafny.Sequence = _dafny.SeqOf()
	_ = _1_dt__update_hholes_h0
	var _2_dt__update_hgrants_h0 _dafny.Sequence = Companion_Default___.StripGrants((g).Dtor_holes(), (g).Dtor_grants())
	_ = _2_dt__update_hgrants_h0
	return m_GoalIr.Companion_Goal_.Create_Goal_((_0_dt__update__tmp_h0).Dtor_v(), (_0_dt__update__tmp_h0).Dtor_principal(), (_0_dt__update__tmp_h0).Dtor_ontDigest(), (_0_dt__update__tmp_h0).Dtor_nlDigest(), (_0_dt__update__tmp_h0).Dtor_sources(), _2_dt__update_hgrants_h0, (_0_dt__update__tmp_h0).Dtor_prohibits(), (_0_dt__update__tmp_h0).Dtor_bounds(), (_0_dt__update__tmp_h0).Dtor_validity(), (_0_dt__update__tmp_h0).Dtor_deleg(), (_0_dt__update__tmp_h0).Dtor_escalateOn(), (_0_dt__update__tmp_h0).Dtor_wildcardAck(), _1_dt__update_hholes_h0)
}
func (_static *CompanionStruct_Default___) BadGrants(ont m_GoalIr.Ontology, g m_GoalIr.Goal, gs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((gs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if m_GoalIr.Companion_Default___.GrantOk(ont, g, (gs).Select(0).(m_GoalIr.Grant)) {
				return _dafny.SeqOf()
			}
			return _dafny.SeqOf(((gs).Select(0).(m_GoalIr.Grant)).Dtor_gid())
		})())
		var _in0 m_GoalIr.Ontology = ont
		_ = _in0
		var _in1 m_GoalIr.Goal = g
		_ = _in1
		var _in2 _dafny.Sequence = (gs).Drop(1)
		_ = _in2
		ont = _in0
		g = _in1
		gs = _in2
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) BadProhibits(ont m_GoalIr.Ontology, ps _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((ps).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if m_GoalIr.Companion_Default___.ProhibitOk(ont, (ps).Select(0).(m_GoalIr.Prohibit)) {
				return _dafny.SeqOf()
			}
			return _dafny.SeqOf(((ps).Select(0).(m_GoalIr.Prohibit)).Dtor_pid())
		})())
		var _in0 m_GoalIr.Ontology = ont
		_ = _in0
		var _in1 _dafny.Sequence = (ps).Drop(1)
		_ = _in1
		ont = _in0
		ps = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) BadBounds(ont m_GoalIr.Ontology, g m_GoalIr.Goal, bs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((bs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if m_GoalIr.Companion_Default___.BoundOk(ont, g, (bs).Select(0).(m_GoalIr.Bound)) {
				return _dafny.SeqOf()
			}
			return _dafny.SeqOf(((bs).Select(0).(m_GoalIr.Bound)).Dtor_bid())
		})())
		var _in0 m_GoalIr.Ontology = ont
		_ = _in0
		var _in1 m_GoalIr.Goal = g
		_ = _in1
		var _in2 _dafny.Sequence = (bs).Drop(1)
		_ = _in2
		ont = _in0
		g = _in1
		bs = _in2
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) BadHoles(g m_GoalIr.Goal, hs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((hs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if m_GoalIr.Companion_Default___.HoleOk(g, (hs).Select(0).(m_GoalIr.Hole)) {
				return _dafny.SeqOf()
			}
			return _dafny.SeqOf(((hs).Select(0).(m_GoalIr.Hole)).Dtor_hid())
		})())
		var _in0 m_GoalIr.Goal = g
		_ = _in0
		var _in1 _dafny.Sequence = (hs).Drop(1)
		_ = _in1
		g = _in0
		hs = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) TypeReasons(ont m_GoalIr.Ontology, g m_GoalIr.Goal) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate((func() _dafny.Sequence {
		if m_GoalIr.Companion_Default___.Sorted4(g) {
			return _dafny.SeqOf()
		}
		return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("not_canonical_order"))
	})(), (func() _dafny.Sequence {
		if (_dafny.IntOfUint32((Companion_Default___.BadGrants(ont, g, (g).Dtor_grants())).Cardinality())).Sign() == 0 {
			return _dafny.SeqOf()
		}
		return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("ill_typed_grant"))
	})()), (func() _dafny.Sequence {
		if (_dafny.IntOfUint32((Companion_Default___.BadProhibits(ont, (g).Dtor_prohibits())).Cardinality())).Sign() == 0 {
			return _dafny.SeqOf()
		}
		return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("ill_typed_prohibit"))
	})()), (func() _dafny.Sequence {
		if (_dafny.IntOfUint32((Companion_Default___.BadBounds(ont, g, (g).Dtor_bounds())).Cardinality())).Sign() == 0 {
			return _dafny.SeqOf()
		}
		return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("ill_typed_bound"))
	})()), (func() _dafny.Sequence {
		if m_GoalIr.Companion_Default___.EscsTyped(ont, g) {
			return _dafny.SeqOf()
		}
		return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("ill_typed_escalation"))
	})()), (func() _dafny.Sequence {
		if m_GoalIr.Companion_Default___.ValidityOk((g).Dtor_validity(), (g).Dtor_deleg(), g) {
			return _dafny.SeqOf()
		}
		return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("bad_validity_or_delegation"))
	})()), (func() _dafny.Sequence {
		if (_dafny.IntOfUint32((Companion_Default___.BadHoles(g, (g).Dtor_holes())).Cardinality())).Sign() == 0 {
			return _dafny.SeqOf()
		}
		return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("bad_hole"))
	})())
}
func (_static *CompanionStruct_Default___) Compile(ont m_GoalIr.Ontology, g m_GoalIr.Goal) CResult {
	var _0_rs _dafny.Sequence = Companion_Default___.TypeReasons(ont, g)
	_ = _0_rs
	if (_dafny.IntOfUint32((_0_rs).Cardinality())).Sign() == 1 {
		return Companion_CResult_.Create_CEscalate_(_0_rs)
	} else {
		return Companion_CResult_.Create_Compiled_(Companion_Default___.Lower(ont, Companion_Default___.Strip(g)))
	}
}
func (_static *CompanionStruct_Default___) ResNarrows(p2 m_GoalIr.ResPat, p1 m_GoalIr.ResPat) bool {
	return ((p1).Is_PStar()) || ((((p2).Is_PSet()) && ((p1).Is_PSet())) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((p2).Dtor_ids()).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32(((p2).Dtor_ids()).Cardinality())) < 0)) || (_dafny.Companion_Sequence_.Contains((p1).Dtor_ids(), ((p2).Dtor_ids()).Select((_0_i).Uint32()).(_dafny.Sequence)))
	})))
}
func (_static *CompanionStruct_Default___) CondNarrows(c2 m_GoalIr.Cond, c1 m_GoalIr.Cond) bool {
	return ((c2).Equals(c1)) || (((c2).Is_And()) && ((((c2).Dtor_a()).Equals(c1)) || (((c2).Dtor_b()).Equals(c1))))
}
func (_static *CompanionStruct_Default___) GrantNarrows(ont m_GoalIr.Ontology, g2 m_GoalIr.Grant, g1 m_GoalIr.Grant) bool {
	return (((_dafny.Companion_Sequence_.Equal((g2).Dtor_gid(), (g1).Dtor_gid())) && (_dafny.Companion_Sequence_.Equal((g2).Dtor_verb(), (g1).Dtor_verb()))) && (Companion_Default___.ResNarrows(m_GoalIr.Companion_Default___.ResolveSel(ont, (g2).Dtor_res()), m_GoalIr.Companion_Default___.ResolveSel(ont, (g1).Dtor_res())))) && (Companion_Default___.CondNarrows((g2).Dtor_cond(), (g1).Dtor_cond()))
}
func (_static *CompanionStruct_Default___) SubsetOf(xs _dafny.Sequence, ys _dafny.Sequence) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((xs).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((xs).Cardinality())) < 0)) || (_dafny.Companion_Sequence_.Contains(ys, (xs).Select((_0_i).Uint32()).(interface{})))
	})
}
func (_static *CompanionStruct_Default___) Refines(ont m_GoalIr.Ontology, g2 m_GoalIr.Goal, g1 m_GoalIr.Goal) bool {
	return ((((((((_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g2).Dtor_grants()).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32(((g2).Dtor_grants()).Cardinality())) < 0)) || (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g1).Dtor_grants()).Cardinality())), false, func(_exists_var_0 _dafny.Int) bool {
			var _1_j _dafny.Int
			_1_j = interface{}(_exists_var_0).(_dafny.Int)
			return (((_1_j).Sign() != -1) && ((_1_j).Cmp(_dafny.IntOfUint32(((g1).Dtor_grants()).Cardinality())) < 0)) && (Companion_Default___.GrantNarrows(ont, ((g2).Dtor_grants()).Select((_0_i).Uint32()).(m_GoalIr.Grant), ((g1).Dtor_grants()).Select((_1_j).Uint32()).(m_GoalIr.Grant)))
		}))
	})) && (Companion_Default___.SubsetOf((g1).Dtor_prohibits(), (g2).Dtor_prohibits()))) && (Companion_Default___.SubsetOf((g1).Dtor_bounds(), (g2).Dtor_bounds()))) && (Companion_Default___.SubsetOf((g1).Dtor_escalateOn(), (g2).Dtor_escalateOn()))) && ((((g2).Dtor_validity()).Dtor_notBefore()).Cmp(((g1).Dtor_validity()).Dtor_notBefore()) >= 0)) && ((((g2).Dtor_validity()).Dtor_notAfter()).Cmp(((g1).Dtor_validity()).Dtor_notAfter()) <= 0)) && (((((g1).Dtor_validity()).Dtor_maxIdle()).Sign() != 1) || (((((g2).Dtor_validity()).Dtor_maxIdle()).Sign() == 1) && ((((g2).Dtor_validity()).Dtor_maxIdle()).Cmp(((g1).Dtor_validity()).Dtor_maxIdle()) <= 0)))) && ((((g2).Dtor_deleg()).Dtor_maxDepth()).Cmp(((g1).Dtor_deleg()).Dtor_maxDepth()) <= 0)) && (Companion_Default___.SubsetOf(((g2).Dtor_deleg()).Dtor_mayTouch(), ((g1).Dtor_deleg()).Dtor_mayTouch()))
}
func (_static *CompanionStruct_Default___) BoundOne(ont m_GoalIr.Ontology, b m_GoalIr.Bound, gid _dafny.Sequence, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Int {
	var _0_s m_GoalIr.LSel = m_GoalIr.Companion_Default___.ResolveBSel(ont, (b).Dtor_sel())
	_ = _0_s
	if m_GoalIr.Companion_Default___.AppliesL(_0_s, gid, (a).Dtor_verb()) {
		return m_GoalIr.Companion_Default___.BoundStat((b).Dtor_core(), _0_s, a, h)
	} else {
		return m_GoalIr.Companion_Default___.Allow()
	}
}
func (_static *CompanionStruct_Default___) Refines2V(g2 m_GoalIr.Goal, g1 m_GoalIr.Goal) bool {
	return ((((((g2).Dtor_validity()).Dtor_notBefore()).Cmp(((g1).Dtor_validity()).Dtor_notBefore()) >= 0) && ((((g2).Dtor_validity()).Dtor_notAfter()).Cmp(((g1).Dtor_validity()).Dtor_notAfter()) <= 0)) && (((((g1).Dtor_validity()).Dtor_maxIdle()).Sign() != 1) || (((((g2).Dtor_validity()).Dtor_maxIdle()).Sign() == 1) && ((((g2).Dtor_validity()).Dtor_maxIdle()).Cmp(((g1).Dtor_validity()).Dtor_maxIdle()) <= 0)))) && ((((g2).Dtor_deleg()).Dtor_maxDepth()).Cmp(((g1).Dtor_deleg()).Dtor_maxDepth()) <= 0)
}

// End of class Default__

// Definition of datatype NC
type NC struct {
	Data_NC_
}

func (_this NC) Get_() Data_NC_ {
	return _this.Data_NC_
}

type Data_NC_ interface {
	isNC()
}

type CompanionStruct_NC_ struct {
}

var Companion_NC_ = CompanionStruct_NC_{}

type NC_NTrue struct {
}

func (NC_NTrue) isNC() {}

func (CompanionStruct_NC_) Create_NTrue_() NC {
	return NC{NC_NTrue{}}
}

func (_this NC) Is_NTrue() bool {
	_, ok := _this.Get_().(NC_NTrue)
	return ok
}

type NC_NFalse struct {
}

func (NC_NFalse) isNC() {}

func (CompanionStruct_NC_) Create_NFalse_() NC {
	return NC{NC_NFalse{}}
}

func (_this NC) Is_NFalse() bool {
	_, ok := _this.Get_().(NC_NFalse)
	return ok
}

type NC_NAtom struct {
	Op m_GoalIr.Op
	L  m_GoalIr.Term
	R  m_GoalIr.Term
}

func (NC_NAtom) isNC() {}

func (CompanionStruct_NC_) Create_NAtom_(Op m_GoalIr.Op, L m_GoalIr.Term, R m_GoalIr.Term) NC {
	return NC{NC_NAtom{Op, L, R}}
}

func (_this NC) Is_NAtom() bool {
	_, ok := _this.Get_().(NC_NAtom)
	return ok
}

type NC_NAnd struct {
	A NC
	B NC
}

func (NC_NAnd) isNC() {}

func (CompanionStruct_NC_) Create_NAnd_(A NC, B NC) NC {
	return NC{NC_NAnd{A, B}}
}

func (_this NC) Is_NAnd() bool {
	_, ok := _this.Get_().(NC_NAnd)
	return ok
}

type NC_NOr struct {
	A NC
	B NC
}

func (NC_NOr) isNC() {}

func (CompanionStruct_NC_) Create_NOr_(A NC, B NC) NC {
	return NC{NC_NOr{A, B}}
}

func (_this NC) Is_NOr() bool {
	_, ok := _this.Get_().(NC_NOr)
	return ok
}

func (CompanionStruct_NC_) Default() NC {
	return Companion_NC_.Create_NTrue_()
}

func (_this NC) Dtor_op() m_GoalIr.Op {
	return _this.Get_().(NC_NAtom).Op
}

func (_this NC) Dtor_l() m_GoalIr.Term {
	return _this.Get_().(NC_NAtom).L
}

func (_this NC) Dtor_r() m_GoalIr.Term {
	return _this.Get_().(NC_NAtom).R
}

func (_this NC) Dtor_a() NC {
	switch data := _this.Get_().(type) {
	case NC_NAnd:
		return data.A
	default:
		return data.(NC_NOr).A
	}
}

func (_this NC) Dtor_b() NC {
	switch data := _this.Get_().(type) {
	case NC_NAnd:
		return data.B
	default:
		return data.(NC_NOr).B
	}
}

func (_this NC) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case NC_NTrue:
		{
			return "GoalCompile.NC.NTrue"
		}
	case NC_NFalse:
		{
			return "GoalCompile.NC.NFalse"
		}
	case NC_NAtom:
		{
			return "GoalCompile.NC.NAtom" + "(" + _dafny.String(data.Op) + ", " + _dafny.String(data.L) + ", " + _dafny.String(data.R) + ")"
		}
	case NC_NAnd:
		{
			return "GoalCompile.NC.NAnd" + "(" + _dafny.String(data.A) + ", " + _dafny.String(data.B) + ")"
		}
	case NC_NOr:
		{
			return "GoalCompile.NC.NOr" + "(" + _dafny.String(data.A) + ", " + _dafny.String(data.B) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this NC) Equals(other NC) bool {
	switch data1 := _this.Get_().(type) {
	case NC_NTrue:
		{
			_, ok := other.Get_().(NC_NTrue)
			return ok
		}
	case NC_NFalse:
		{
			_, ok := other.Get_().(NC_NFalse)
			return ok
		}
	case NC_NAtom:
		{
			data2, ok := other.Get_().(NC_NAtom)
			return ok && data1.Op.Equals(data2.Op) && data1.L.Equals(data2.L) && data1.R.Equals(data2.R)
		}
	case NC_NAnd:
		{
			data2, ok := other.Get_().(NC_NAnd)
			return ok && data1.A.Equals(data2.A) && data1.B.Equals(data2.B)
		}
	case NC_NOr:
		{
			data2, ok := other.Get_().(NC_NOr)
			return ok && data1.A.Equals(data2.A) && data1.B.Equals(data2.B)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this NC) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(NC)
	return ok && _this.Equals(typed)
}

func Type_NC_() _dafny.TypeDescriptor {
	return type_NC_{}
}

type type_NC_ struct {
}

func (_this type_NC_) Default() interface{} {
	return Companion_NC_.Default()
}

func (_this type_NC_) String() string {
	return "GoalCompile.NC"
}
func (_this NC) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = NC{}

// End of datatype NC

// Definition of datatype LPred
type LPred struct {
	Data_LPred_
}

func (_this LPred) Get_() Data_LPred_ {
	return _this.Data_LPred_
}

type Data_LPred_ interface {
	isLPred()
}

type CompanionStruct_LPred_ struct {
}

var Companion_LPred_ = CompanionStruct_LPred_{}

type LPred_LPred struct {
	Gid  _dafny.Sequence
	Verb _dafny.Sequence
	Res  m_GoalIr.ResPat
	Cond NC
}

func (LPred_LPred) isLPred() {}

func (CompanionStruct_LPred_) Create_LPred_(Gid _dafny.Sequence, Verb _dafny.Sequence, Res m_GoalIr.ResPat, Cond NC) LPred {
	return LPred{LPred_LPred{Gid, Verb, Res, Cond}}
}

func (_this LPred) Is_LPred() bool {
	_, ok := _this.Get_().(LPred_LPred)
	return ok
}

func (CompanionStruct_LPred_) Default() LPred {
	return Companion_LPred_.Create_LPred_(_dafny.EmptySeq, _dafny.EmptySeq, m_GoalIr.Companion_ResPat_.Default(), Companion_NC_.Default())
}

func (_this LPred) Dtor_gid() _dafny.Sequence {
	return _this.Get_().(LPred_LPred).Gid
}

func (_this LPred) Dtor_verb() _dafny.Sequence {
	return _this.Get_().(LPred_LPred).Verb
}

func (_this LPred) Dtor_res() m_GoalIr.ResPat {
	return _this.Get_().(LPred_LPred).Res
}

func (_this LPred) Dtor_cond() NC {
	return _this.Get_().(LPred_LPred).Cond
}

func (_this LPred) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case LPred_LPred:
		{
			return "GoalCompile.LPred.LPred" + "(" + data.Gid.VerbatimString(true) + ", " + data.Verb.VerbatimString(true) + ", " + _dafny.String(data.Res) + ", " + _dafny.String(data.Cond) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this LPred) Equals(other LPred) bool {
	switch data1 := _this.Get_().(type) {
	case LPred_LPred:
		{
			data2, ok := other.Get_().(LPred_LPred)
			return ok && data1.Gid.Equals(data2.Gid) && data1.Verb.Equals(data2.Verb) && data1.Res.Equals(data2.Res) && data1.Cond.Equals(data2.Cond)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this LPred) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(LPred)
	return ok && _this.Equals(typed)
}

func Type_LPred_() _dafny.TypeDescriptor {
	return type_LPred_{}
}

type type_LPred_ struct {
}

func (_this type_LPred_) Default() interface{} {
	return Companion_LPred_.Default()
}

func (_this type_LPred_) String() string {
	return "GoalCompile.LPred"
}
func (_this LPred) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = LPred{}

// End of datatype LPred

// Definition of datatype LProh
type LProh struct {
	Data_LProh_
}

func (_this LProh) Get_() Data_LProh_ {
	return _this.Data_LProh_
}

type Data_LProh_ interface {
	isLProh()
}

type CompanionStruct_LProh_ struct {
}

var Companion_LProh_ = CompanionStruct_LProh_{}

type LProh_LProh struct {
	Pid   _dafny.Sequence
	Verbs _dafny.Sequence
	Res   m_GoalIr.ResPat
	Cond  NC
}

func (LProh_LProh) isLProh() {}

func (CompanionStruct_LProh_) Create_LProh_(Pid _dafny.Sequence, Verbs _dafny.Sequence, Res m_GoalIr.ResPat, Cond NC) LProh {
	return LProh{LProh_LProh{Pid, Verbs, Res, Cond}}
}

func (_this LProh) Is_LProh() bool {
	_, ok := _this.Get_().(LProh_LProh)
	return ok
}

func (CompanionStruct_LProh_) Default() LProh {
	return Companion_LProh_.Create_LProh_(_dafny.EmptySeq, _dafny.EmptySeq, m_GoalIr.Companion_ResPat_.Default(), Companion_NC_.Default())
}

func (_this LProh) Dtor_pid() _dafny.Sequence {
	return _this.Get_().(LProh_LProh).Pid
}

func (_this LProh) Dtor_verbs() _dafny.Sequence {
	return _this.Get_().(LProh_LProh).Verbs
}

func (_this LProh) Dtor_res() m_GoalIr.ResPat {
	return _this.Get_().(LProh_LProh).Res
}

func (_this LProh) Dtor_cond() NC {
	return _this.Get_().(LProh_LProh).Cond
}

func (_this LProh) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case LProh_LProh:
		{
			return "GoalCompile.LProh.LProh" + "(" + data.Pid.VerbatimString(true) + ", " + _dafny.String(data.Verbs) + ", " + _dafny.String(data.Res) + ", " + _dafny.String(data.Cond) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this LProh) Equals(other LProh) bool {
	switch data1 := _this.Get_().(type) {
	case LProh_LProh:
		{
			data2, ok := other.Get_().(LProh_LProh)
			return ok && data1.Pid.Equals(data2.Pid) && data1.Verbs.Equals(data2.Verbs) && data1.Res.Equals(data2.Res) && data1.Cond.Equals(data2.Cond)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this LProh) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(LProh)
	return ok && _this.Equals(typed)
}

func Type_LProh_() _dafny.TypeDescriptor {
	return type_LProh_{}
}

type type_LProh_ struct {
}

func (_this type_LProh_) Default() interface{} {
	return Companion_LProh_.Default()
}

func (_this type_LProh_) String() string {
	return "GoalCompile.LProh"
}
func (_this LProh) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = LProh{}

// End of datatype LProh

// Definition of datatype LCeil
type LCeil struct {
	Data_LCeil_
}

func (_this LCeil) Get_() Data_LCeil_ {
	return _this.Data_LCeil_
}

type Data_LCeil_ interface {
	isLCeil()
}

type CompanionStruct_LCeil_ struct {
}

var Companion_LCeil_ = CompanionStruct_LCeil_{}

type LCeil_LCeil struct {
	Bid  _dafny.Sequence
	Sel  m_GoalIr.LSel
	Core m_GoalIr.BCore
}

func (LCeil_LCeil) isLCeil() {}

func (CompanionStruct_LCeil_) Create_LCeil_(Bid _dafny.Sequence, Sel m_GoalIr.LSel, Core m_GoalIr.BCore) LCeil {
	return LCeil{LCeil_LCeil{Bid, Sel, Core}}
}

func (_this LCeil) Is_LCeil() bool {
	_, ok := _this.Get_().(LCeil_LCeil)
	return ok
}

func (CompanionStruct_LCeil_) Default() LCeil {
	return Companion_LCeil_.Create_LCeil_(_dafny.EmptySeq, m_GoalIr.Companion_LSel_.Default(), m_GoalIr.Companion_BCore_.Default())
}

func (_this LCeil) Dtor_bid() _dafny.Sequence {
	return _this.Get_().(LCeil_LCeil).Bid
}

func (_this LCeil) Dtor_sel() m_GoalIr.LSel {
	return _this.Get_().(LCeil_LCeil).Sel
}

func (_this LCeil) Dtor_core() m_GoalIr.BCore {
	return _this.Get_().(LCeil_LCeil).Core
}

func (_this LCeil) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case LCeil_LCeil:
		{
			return "GoalCompile.LCeil.LCeil" + "(" + data.Bid.VerbatimString(true) + ", " + _dafny.String(data.Sel) + ", " + _dafny.String(data.Core) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this LCeil) Equals(other LCeil) bool {
	switch data1 := _this.Get_().(type) {
	case LCeil_LCeil:
		{
			data2, ok := other.Get_().(LCeil_LCeil)
			return ok && data1.Bid.Equals(data2.Bid) && data1.Sel.Equals(data2.Sel) && data1.Core.Equals(data2.Core)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this LCeil) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(LCeil)
	return ok && _this.Equals(typed)
}

func Type_LCeil_() _dafny.TypeDescriptor {
	return type_LCeil_{}
}

type type_LCeil_ struct {
}

func (_this type_LCeil_) Default() interface{} {
	return Companion_LCeil_.Default()
}

func (_this type_LCeil_) String() string {
	return "GoalCompile.LCeil"
}
func (_this LCeil) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = LCeil{}

// End of datatype LCeil

// Definition of datatype Pol
type Pol struct {
	Data_Pol_
}

func (_this Pol) Get_() Data_Pol_ {
	return _this.Data_Pol_
}

type Data_Pol_ interface {
	isPol()
}

type CompanionStruct_Pol_ struct {
}

var Companion_Pol_ = CompanionStruct_Pol_{}

type Pol_Pol struct {
	Preds    _dafny.Sequence
	Prohs    _dafny.Sequence
	Ceils    _dafny.Sequence
	Escs     _dafny.Sequence
	Validity m_GoalIr.Validity
	Deleg    m_GoalIr.Delegation
}

func (Pol_Pol) isPol() {}

func (CompanionStruct_Pol_) Create_Pol_(Preds _dafny.Sequence, Prohs _dafny.Sequence, Ceils _dafny.Sequence, Escs _dafny.Sequence, Validity m_GoalIr.Validity, Deleg m_GoalIr.Delegation) Pol {
	return Pol{Pol_Pol{Preds, Prohs, Ceils, Escs, Validity, Deleg}}
}

func (_this Pol) Is_Pol() bool {
	_, ok := _this.Get_().(Pol_Pol)
	return ok
}

func (CompanionStruct_Pol_) Default() Pol {
	return Companion_Pol_.Create_Pol_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, m_GoalIr.Companion_Validity_.Default(), m_GoalIr.Companion_Delegation_.Default())
}

func (_this Pol) Dtor_preds() _dafny.Sequence {
	return _this.Get_().(Pol_Pol).Preds
}

func (_this Pol) Dtor_prohs() _dafny.Sequence {
	return _this.Get_().(Pol_Pol).Prohs
}

func (_this Pol) Dtor_ceils() _dafny.Sequence {
	return _this.Get_().(Pol_Pol).Ceils
}

func (_this Pol) Dtor_escs() _dafny.Sequence {
	return _this.Get_().(Pol_Pol).Escs
}

func (_this Pol) Dtor_validity() m_GoalIr.Validity {
	return _this.Get_().(Pol_Pol).Validity
}

func (_this Pol) Dtor_deleg() m_GoalIr.Delegation {
	return _this.Get_().(Pol_Pol).Deleg
}

func (_this Pol) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Pol_Pol:
		{
			return "GoalCompile.Pol.Pol" + "(" + _dafny.String(data.Preds) + ", " + _dafny.String(data.Prohs) + ", " + _dafny.String(data.Ceils) + ", " + _dafny.String(data.Escs) + ", " + _dafny.String(data.Validity) + ", " + _dafny.String(data.Deleg) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Pol) Equals(other Pol) bool {
	switch data1 := _this.Get_().(type) {
	case Pol_Pol:
		{
			data2, ok := other.Get_().(Pol_Pol)
			return ok && data1.Preds.Equals(data2.Preds) && data1.Prohs.Equals(data2.Prohs) && data1.Ceils.Equals(data2.Ceils) && data1.Escs.Equals(data2.Escs) && data1.Validity.Equals(data2.Validity) && data1.Deleg.Equals(data2.Deleg)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Pol) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Pol)
	return ok && _this.Equals(typed)
}

func Type_Pol_() _dafny.TypeDescriptor {
	return type_Pol_{}
}

type type_Pol_ struct {
}

func (_this type_Pol_) Default() interface{} {
	return Companion_Pol_.Default()
}

func (_this type_Pol_) String() string {
	return "GoalCompile.Pol"
}
func (_this Pol) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Pol{}

// End of datatype Pol

// Definition of datatype CResult
type CResult struct {
	Data_CResult_
}

func (_this CResult) Get_() Data_CResult_ {
	return _this.Data_CResult_
}

type Data_CResult_ interface {
	isCResult()
}

type CompanionStruct_CResult_ struct {
}

var Companion_CResult_ = CompanionStruct_CResult_{}

type CResult_Compiled struct {
	P Pol
}

func (CResult_Compiled) isCResult() {}

func (CompanionStruct_CResult_) Create_Compiled_(P Pol) CResult {
	return CResult{CResult_Compiled{P}}
}

func (_this CResult) Is_Compiled() bool {
	_, ok := _this.Get_().(CResult_Compiled)
	return ok
}

type CResult_CEscalate struct {
	Reasons _dafny.Sequence
}

func (CResult_CEscalate) isCResult() {}

func (CompanionStruct_CResult_) Create_CEscalate_(Reasons _dafny.Sequence) CResult {
	return CResult{CResult_CEscalate{Reasons}}
}

func (_this CResult) Is_CEscalate() bool {
	_, ok := _this.Get_().(CResult_CEscalate)
	return ok
}

func (CompanionStruct_CResult_) Default() CResult {
	return Companion_CResult_.Create_Compiled_(Companion_Pol_.Default())
}

func (_this CResult) Dtor_p() Pol {
	return _this.Get_().(CResult_Compiled).P
}

func (_this CResult) Dtor_reasons() _dafny.Sequence {
	return _this.Get_().(CResult_CEscalate).Reasons
}

func (_this CResult) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case CResult_Compiled:
		{
			return "GoalCompile.CResult.Compiled" + "(" + _dafny.String(data.P) + ")"
		}
	case CResult_CEscalate:
		{
			return "GoalCompile.CResult.CEscalate" + "(" + _dafny.String(data.Reasons) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this CResult) Equals(other CResult) bool {
	switch data1 := _this.Get_().(type) {
	case CResult_Compiled:
		{
			data2, ok := other.Get_().(CResult_Compiled)
			return ok && data1.P.Equals(data2.P)
		}
	case CResult_CEscalate:
		{
			data2, ok := other.Get_().(CResult_CEscalate)
			return ok && data1.Reasons.Equals(data2.Reasons)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this CResult) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(CResult)
	return ok && _this.Equals(typed)
}

func Type_CResult_() _dafny.TypeDescriptor {
	return type_CResult_{}
}

type type_CResult_ struct {
}

func (_this type_CResult_) Default() interface{} {
	return Companion_CResult_.Default()
}

func (_this type_CResult_) String() string {
	return "GoalCompile.CResult"
}
func (_this CResult) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = CResult{}

// End of datatype CResult
