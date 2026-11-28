// Package GoalIr
// Dafny module GoalIr compiled into Go

package GoalIr

import (
	m__System "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/System_"
	_dafny "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/dafny"
	os "os"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__

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
	return "GoalIr.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) MeetD(a _dafny.Int, b _dafny.Int) _dafny.Int {
	if (a).Cmp(b) <= 0 {
		return a
	} else {
		return b
	}
}
func (_static *CompanionStruct_Default___) JoinD(a _dafny.Int, b _dafny.Int) _dafny.Int {
	if (a).Cmp(b) >= 0 {
		return a
	} else {
		return b
	}
}
func (_static *CompanionStruct_Default___) AndK(a _dafny.Int, b _dafny.Int) _dafny.Int {
	if (a).Cmp(b) <= 0 {
		return a
	} else {
		return b
	}
}
func (_static *CompanionStruct_Default___) OrK(a _dafny.Int, b _dafny.Int) _dafny.Int {
	if (a).Cmp(b) >= 0 {
		return a
	} else {
		return b
	}
}
func (_static *CompanionStruct_Default___) NotK(a _dafny.Int) _dafny.Int {
	return (_dafny.IntOfInt64(2)).Minus(a)
}
func (_static *CompanionStruct_Default___) B2T(b bool) _dafny.Int {
	if b {
		return Companion_Default___.KT()
	} else {
		return Companion_Default___.KF()
	}
}
func (_static *CompanionStruct_Default___) DecOfTri(t _dafny.Int) _dafny.Int {
	return t
}
func (_static *CompanionStruct_Default___) AtomV(a Atom) V {
	var _source0 Atom = a
	_ = _source0
	{
		if _source0.Is_AQ() {
			var _0_q Q = _source0.Get_().(Atom_AQ).Q
			_ = _0_q
			return Companion_V_.Create_VQ_(_0_q)
		}
	}
	{
		var _1_s _dafny.Sequence = _source0.Get_().(Atom_AS).S
		_ = _1_s
		return Companion_V_.Create_VS_(_1_s)
	}
}
func (_static *CompanionStruct_Default___) TypeOfV(v V) Option {
	var _source0 V = v
	_ = _source0
	{
		if _source0.Is_VQ() {
			var _0_q Q = _source0.Get_().(V_VQ).Q
			_ = _0_q
			return Companion_Option_.Create_Some_(Companion_Ty_.Create_TyQ_((_0_q).Dtor_u()))
		}
	}
	{
		if _source0.Is_VS() {
			return Companion_Option_.Create_Some_(Companion_Ty_.Create_TyS_())
		}
	}
	{
		return Companion_Option_.Create_None_()
	}
}
func (_static *CompanionStruct_Default___) ResOk(p ResPat, r _dafny.Sequence) bool {
	var _source0 ResPat = p
	_ = _source0
	{
		if _source0.Is_PStar() {
			return true
		}
	}
	{
		var _0_ids _dafny.Sequence = _source0.Get_().(ResPat_PSet).Ids
		_ = _0_ids
		return _dafny.Companion_Sequence_.Contains(_0_ids, r)
	}
}
func (_static *CompanionStruct_Default___) RelMembers(rels _dafny.Sequence, rel _dafny.Sequence, anchor _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((rels).Cardinality())).Sign() == 0 {
		return _dafny.SeqOf()
	} else if (_dafny.Companion_Sequence_.Equal(((rels).Select(0).(RelDecl)).Dtor_rel(), rel)) && (_dafny.Companion_Sequence_.Equal(((rels).Select(0).(RelDecl)).Dtor_anchor(), anchor)) {
		return ((rels).Select(0).(RelDecl)).Dtor_members()
	} else {
		var _in0 _dafny.Sequence = (rels).Drop(1)
		_ = _in0
		var _in1 _dafny.Sequence = rel
		_ = _in1
		var _in2 _dafny.Sequence = anchor
		_ = _in2
		rels = _in0
		rel = _in1
		anchor = _in2
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) ResolveSel(ont Ontology, s ResSel) ResPat {
	var _source0 ResSel = s
	_ = _source0
	{
		if _source0.Is_Exact() {
			var _0_id _dafny.Sequence = _source0.Get_().(ResSel_Exact).Id
			_ = _0_id
			return Companion_ResPat_.Create_PSet_(_dafny.SeqOf(_0_id))
		}
	}
	{
		if _source0.Is_OneOf() {
			var _1_ids _dafny.Sequence = _source0.Get_().(ResSel_OneOf).Ids
			_ = _1_ids
			return Companion_ResPat_.Create_PSet_(_1_ids)
		}
	}
	{
		if _source0.Is_Related() {
			var _2_rel _dafny.Sequence = _source0.Get_().(ResSel_Related).Rel
			_ = _2_rel
			var _3_anchor _dafny.Sequence = _source0.Get_().(ResSel_Related).Anchor
			_ = _3_anchor
			return Companion_ResPat_.Create_PSet_(Companion_Default___.RelMembers((ont).Dtor_rels(), _2_rel, _3_anchor))
		}
	}
	{
		if _source0.Is_AnyRes() {
			return Companion_ResPat_.Create_PStar_()
		}
	}
	{
		var _4_ps _dafny.Sequence = _source0.Get_().(ResSel_AllOf).Parts
		_ = _4_ps
		return Companion_Default___.ResolveParts(ont, _4_ps)
	}
}
func (_static *CompanionStruct_Default___) ResolvePart(ont Ontology, p ResPart) ResPat {
	var _source0 ResPart = p
	_ = _source0
	{
		if _source0.Is_PartExact() {
			var _0_id _dafny.Sequence = _source0.Get_().(ResPart_PartExact).Id
			_ = _0_id
			return Companion_ResPat_.Create_PSet_(_dafny.SeqOf(_0_id))
		}
	}
	{
		if _source0.Is_PartOneOf() {
			var _1_ids _dafny.Sequence = _source0.Get_().(ResPart_PartOneOf).Ids
			_ = _1_ids
			return Companion_ResPat_.Create_PSet_(_1_ids)
		}
	}
	{
		var _2_rel _dafny.Sequence = _source0.Get_().(ResPart_PartRelated).Rel
		_ = _2_rel
		var _3_anchor _dafny.Sequence = _source0.Get_().(ResPart_PartRelated).Anchor
		_ = _3_anchor
		return Companion_ResPat_.Create_PSet_(Companion_Default___.RelMembers((ont).Dtor_rels(), _2_rel, _3_anchor))
	}
}
func (_static *CompanionStruct_Default___) FilterIn(a _dafny.Sequence, b _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((a).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if _dafny.Companion_Sequence_.Contains(b, (a).Select(0).(_dafny.Sequence)) {
				return _dafny.SeqOf((a).Select(0).(_dafny.Sequence))
			}
			return _dafny.SeqOf()
		})())
		var _in0 _dafny.Sequence = (a).Drop(1)
		_ = _in0
		var _in1 _dafny.Sequence = b
		_ = _in1
		a = _in0
		b = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) InterPat(x ResPat, y ResPat) ResPat {
	var _source0 ResPat = x
	_ = _source0
	{
		if _source0.Is_PStar() {
			return y
		}
	}
	{
		var _0_a _dafny.Sequence = _source0.Get_().(ResPat_PSet).Ids
		_ = _0_a
		var _source1 ResPat = y
		_ = _source1
		{
			if _source1.Is_PStar() {
				return x
			}
		}
		{
			var _1_b _dafny.Sequence = _source1.Get_().(ResPat_PSet).Ids
			_ = _1_b
			return Companion_ResPat_.Create_PSet_(Companion_Default___.FilterIn(_0_a, _1_b))
		}
	}
}
func (_static *CompanionStruct_Default___) ResolveParts(ont Ontology, ps _dafny.Sequence) ResPat {
	if (_dafny.IntOfUint32((ps).Cardinality())).Sign() == 0 {
		return Companion_ResPat_.Create_PStar_()
	} else {
		return Companion_Default___.InterPat(Companion_Default___.ResolvePart(ont, (ps).Select(0).(ResPart)), Companion_Default___.ResolveParts(ont, (ps).Drop(1)))
	}
}
func (_static *CompanionStruct_Default___) VerbsOfClass(vs _dafny.Sequence, cls _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((vs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if _dafny.Companion_Sequence_.Equal(((vs).Select(0).(VerbDecl)).Dtor_cls(), cls) {
				return _dafny.SeqOf(((vs).Select(0).(VerbDecl)).Dtor_verb())
			}
			return _dafny.SeqOf()
		})())
		var _in0 _dafny.Sequence = (vs).Drop(1)
		_ = _in0
		var _in1 _dafny.Sequence = cls
		_ = _in1
		vs = _in0
		cls = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) ResolveBSel(ont Ontology, s Sel) LSel {
	var _source0 Sel = s
	_ = _source0
	{
		if _source0.Is_SelGids() {
			var _0_g _dafny.Sequence = _source0.Get_().(Sel_SelGids).Gids
			_ = _0_g
			return Companion_LSel_.Create_LSel_(_0_g, _dafny.SeqOf())
		}
	}
	{
		var _1_c _dafny.Sequence = _source0.Get_().(Sel_SelEffect).Cls
		_ = _1_c
		return Companion_LSel_.Create_LSel_(_dafny.SeqOf(), Companion_Default___.VerbsOfClass((ont).Dtor_verbs(), _1_c))
	}
}
func (_static *CompanionStruct_Default___) ProhVerbs(ont Ontology, t ProhTarget) _dafny.Sequence {
	var _source0 ProhTarget = t
	_ = _source0
	{
		if _source0.Is_PVerb() {
			var _0_v _dafny.Sequence = _source0.Get_().(ProhTarget_PVerb).Verb
			_ = _0_v
			return _dafny.SeqOf(_0_v)
		}
	}
	{
		var _1_c _dafny.Sequence = _source0.Get_().(ProhTarget_PEffect).Cls
		_ = _1_c
		return Companion_Default___.VerbsOfClass((ont).Dtor_verbs(), _1_c)
	}
}
func (_static *CompanionStruct_Default___) EqT(x V, y V) _dafny.Int {
	var _source0 V = x
	_ = _source0
	{
		if _source0.Is_VQ() {
			var _0_p Q = _source0.Get_().(V_VQ).Q
			_ = _0_p
			var _source1 V = y
			_ = _source1
			{
				if _source1.Is_VQ() {
					var _1_q Q = _source1.Get_().(V_VQ).Q
					_ = _1_q
					if ((_0_p).Dtor_u()).Equals((_1_q).Dtor_u()) {
						return Companion_Default___.B2T(((_0_p).Dtor_n()).Cmp((_1_q).Dtor_n()) == 0)
					} else {
						return Companion_Default___.KU()
					}
				}
			}
			{
				return Companion_Default___.KU()
			}
		}
	}
	{
		if _source0.Is_VS() {
			var _2_s _dafny.Sequence = _source0.Get_().(V_VS).S
			_ = _2_s
			var _source2 V = y
			_ = _source2
			{
				if _source2.Is_VS() {
					var _3_t _dafny.Sequence = _source2.Get_().(V_VS).S
					_ = _3_t
					return Companion_Default___.B2T(_dafny.Companion_Sequence_.Equal(_2_s, _3_t))
				}
			}
			{
				return Companion_Default___.KU()
			}
		}
	}
	{
		return Companion_Default___.KU()
	}
}
func (_static *CompanionStruct_Default___) LtT(x V, y V) _dafny.Int {
	var _source0 V = x
	_ = _source0
	{
		if _source0.Is_VQ() {
			var _0_p Q = _source0.Get_().(V_VQ).Q
			_ = _0_p
			var _source1 V = y
			_ = _source1
			{
				if _source1.Is_VQ() {
					var _1_q Q = _source1.Get_().(V_VQ).Q
					_ = _1_q
					if ((_0_p).Dtor_u()).Equals((_1_q).Dtor_u()) {
						return Companion_Default___.B2T(((_0_p).Dtor_n()).Cmp((_1_q).Dtor_n()) < 0)
					} else {
						return Companion_Default___.KU()
					}
				}
			}
			{
				return Companion_Default___.KU()
			}
		}
	}
	{
		return Companion_Default___.KU()
	}
}
func (_static *CompanionStruct_Default___) InT(x V, items _dafny.Sequence) _dafny.Int {
	if (_dafny.IntOfUint32((items).Cardinality())).Sign() == 0 {
		return Companion_Default___.KF()
	} else {
		return Companion_Default___.OrK(Companion_Default___.EqT(x, Companion_Default___.AtomV((items).Select(0).(Atom))), Companion_Default___.InT(x, (items).Drop(1)))
	}
}
func (_static *CompanionStruct_Default___) CmpT(op Op, x Option, y Option) _dafny.Int {
	if ((x).Is_None()) || ((y).Is_None()) {
		return Companion_Default___.KU()
	} else {
		var _source0 Op = op
		_ = _source0
		{
			if _source0.Is_Eq() {
				return Companion_Default___.EqT((x).Dtor_v().(V), (y).Dtor_v().(V))
			}
		}
		{
			if _source0.Is_Ne() {
				return Companion_Default___.NotK(Companion_Default___.EqT((x).Dtor_v().(V), (y).Dtor_v().(V)))
			}
		}
		{
			if _source0.Is_Lt() {
				return Companion_Default___.LtT((x).Dtor_v().(V), (y).Dtor_v().(V))
			}
		}
		{
			if _source0.Is_Gte() {
				return Companion_Default___.NotK(Companion_Default___.LtT((x).Dtor_v().(V), (y).Dtor_v().(V)))
			}
		}
		{
			if _source0.Is_Gt() {
				return Companion_Default___.LtT((y).Dtor_v().(V), (x).Dtor_v().(V))
			}
		}
		{
			if _source0.Is_Lte() {
				return Companion_Default___.NotK(Companion_Default___.LtT((y).Dtor_v().(V), (x).Dtor_v().(V)))
			}
		}
		{
			if _source0.Is_In() {
				var _source1 V = (y).Dtor_v().(V)
				_ = _source1
				{
					if _source1.Is_VSet() {
						var _0_items _dafny.Sequence = _source1.Get_().(V_VSet).Items
						_ = _0_items
						return Companion_Default___.InT((x).Dtor_v().(V), _0_items)
					}
				}
				{
					return Companion_Default___.KU()
				}
			}
		}
		{
			return Companion_Default___.NotK(func() _dafny.Int {
				var _source2 V = (y).Dtor_v().(V)
				_ = _source2
				{
					if _source2.Is_VSet() {
						var _1_items _dafny.Sequence = _source2.Get_().(V_VSet).Items
						_ = _1_items
						return Companion_Default___.InT((x).Dtor_v().(V), _1_items)
					}
				}
				{
					return Companion_Default___.KU()
				}
			}())
		}
	}
}
func (_static *CompanionStruct_Default___) NegOp(op Op) Op {
	var _source0 Op = op
	_ = _source0
	{
		if _source0.Is_Eq() {
			return Companion_Op_.Create_Ne_()
		}
	}
	{
		if _source0.Is_Ne() {
			return Companion_Op_.Create_Eq_()
		}
	}
	{
		if _source0.Is_Lt() {
			return Companion_Op_.Create_Gte_()
		}
	}
	{
		if _source0.Is_Gte() {
			return Companion_Op_.Create_Lt_()
		}
	}
	{
		if _source0.Is_Gt() {
			return Companion_Op_.Create_Lte_()
		}
	}
	{
		if _source0.Is_Lte() {
			return Companion_Op_.Create_Gt_()
		}
	}
	{
		if _source0.Is_In() {
			return Companion_Op_.Create_Nin_()
		}
	}
	{
		return Companion_Op_.Create_In_()
	}
}
func (_static *CompanionStruct_Default___) EvalT(t Term, a Act, h Hist) Option {
	var _source0 Term = t
	_ = _source0
	{
		if _source0.Is_Param() {
			var _0_p _dafny.Sequence = _source0.Get_().(Term_Param).Path
			_ = _0_p
			if ((a).Dtor_params()).Contains(_0_p) {
				return Companion_Option_.Create_Some_(((a).Dtor_params()).Get(_0_p).(V))
			} else {
				return Companion_Option_.Create_None_()
			}
		}
	}
	{
		if _source0.Is_Lit() {
			var _1_v V = _source0.Get_().(Term_Lit).V
			_ = _1_v
			return Companion_Option_.Create_Some_(_1_v)
		}
	}
	{
		var _2_b _dafny.Sequence = _source0.Get_().(Term_HistAgg).Bid
		_ = _2_b
		if ((h).Dtor_aggs()).Contains(_2_b) {
			return Companion_Option_.Create_Some_(Companion_V_.Create_VQ_(((h).Dtor_aggs()).Get(_2_b).(Q)))
		} else {
			return Companion_Option_.Create_None_()
		}
	}
}
func (_static *CompanionStruct_Default___) EvalC(c Cond, a Act, h Hist) _dafny.Int {
	var _source0 Cond = c
	_ = _source0
	{
		if _source0.Is_CTrue() {
			return Companion_Default___.KT()
		}
	}
	{
		if _source0.Is_Cmp() {
			var _0_op Op = _source0.Get_().(Cond_Cmp).Op
			_ = _0_op
			var _1_l Term = _source0.Get_().(Cond_Cmp).L
			_ = _1_l
			var _2_r Term = _source0.Get_().(Cond_Cmp).R
			_ = _2_r
			return Companion_Default___.CmpT(_0_op, Companion_Default___.EvalT(_1_l, a, h), Companion_Default___.EvalT(_2_r, a, h))
		}
	}
	{
		if _source0.Is_And() {
			var _3_x Cond = _source0.Get_().(Cond_And).A
			_ = _3_x
			var _4_y Cond = _source0.Get_().(Cond_And).B
			_ = _4_y
			return Companion_Default___.AndK(Companion_Default___.EvalC(_3_x, a, h), Companion_Default___.EvalC(_4_y, a, h))
		}
	}
	{
		if _source0.Is_Or() {
			var _5_x Cond = _source0.Get_().(Cond_Or).A
			_ = _5_x
			var _6_y Cond = _source0.Get_().(Cond_Or).B
			_ = _6_y
			return Companion_Default___.OrK(Companion_Default___.EvalC(_5_x, a, h), Companion_Default___.EvalC(_6_y, a, h))
		}
	}
	{
		var _7_x Cond = _source0.Get_().(Cond_Not).C
		_ = _7_x
		return Companion_Default___.NotK(Companion_Default___.EvalC(_7_x, a, h))
	}
}
func (_static *CompanionStruct_Default___) StrIn(x _dafny.Sequence, s _dafny.Sequence) bool {
	return _dafny.Companion_Sequence_.Contains(s, x)
}
func (_static *CompanionStruct_Default___) AppliesL(s LSel, gid _dafny.Sequence, verb _dafny.Sequence) bool {
	return (_dafny.Companion_Sequence_.Contains((s).Dtor_gids(), gid)) || (_dafny.Companion_Sequence_.Contains((s).Dtor_verbs(), verb))
}
func (_static *CompanionStruct_Default___) InScope(sc Scope, a Act, x Act) bool {
	var _source0 Scope = sc
	_ = _source0
	{
		if _source0.Is_SSession() {
			return _dafny.Companion_Sequence_.Equal((a).Dtor_sess(), (x).Dtor_sess())
		}
	}
	{
		if _source0.Is_SPrincipal() {
			return _dafny.Companion_Sequence_.Equal((a).Dtor_prin(), (x).Dtor_prin())
		}
	}
	{
		if _source0.Is_SOrg() {
			return _dafny.Companion_Sequence_.Equal((a).Dtor_org(), (x).Dtor_org())
		}
	}
	{
		var _0_ag _dafny.Sequence = _source0.Get_().(Scope_SFleet).Agents
		_ = _0_ag
		return (_dafny.Companion_Sequence_.Contains(_0_ag, (a).Dtor_agent())) && (_dafny.Companion_Sequence_.Contains(_0_ag, (x).Dtor_agent()))
	}
}
func (_static *CompanionStruct_Default___) InWindow(w Window, a Act, x Act) bool {
	var _source0 Window = w
	_ = _source0
	{
		if _source0.Is_WTask() {
			return true
		}
	}
	{
		if _source0.Is_WLifetime() {
			return true
		}
	}
	{
		if _source0.Is_WSliding() {
			var _0_ms _dafny.Int = _source0.Get_().(Window_WSliding).Ms
			_ = _0_ms
			return (((x).Dtor_t()).Cmp(((a).Dtor_t()).Minus(_0_ms)) > 0) && (((x).Dtor_t()).Cmp((a).Dtor_t()) <= 0)
		}
	}
	{
		var _1_ms _dafny.Int = _source0.Get_().(Window_WPeriod).Ms
		_ = _1_ms
		var _2_t0 _dafny.Int = _source0.Get_().(Window_WPeriod).T0
		_ = _2_t0
		return ((_1_ms).Sign() == 1) && (((((a).Dtor_t()).Minus(_2_t0)).DivBy(_1_ms)).Cmp((((x).Dtor_t()).Minus(_2_t0)).DivBy(_1_ms)) == 0)
	}
}
func (_static *CompanionStruct_Default___) SelItems(core BCore, s LSel, adms _dafny.Sequence, a Act) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((adms).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf(a))
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if ((Companion_Default___.AppliesL(s, ((adms).Select(0).(Adm)).Dtor_gid(), (((adms).Select(0).(Adm)).Dtor_act()).Dtor_verb())) && (Companion_Default___.InScope((core).Dtor_scope(), a, ((adms).Select(0).(Adm)).Dtor_act()))) && (Companion_Default___.InWindow((core).Dtor_window(), a, ((adms).Select(0).(Adm)).Dtor_act())) {
				return _dafny.SeqOf(((adms).Select(0).(Adm)).Dtor_act())
			}
			return _dafny.SeqOf()
		})())
		var _in0 BCore = core
		_ = _in0
		var _in1 LSel = s
		_ = _in1
		var _in2 _dafny.Sequence = (adms).Drop(1)
		_ = _in2
		var _in3 Act = a
		_ = _in3
		core = _in0
		s = _in1
		adms = _in2
		a = _in3
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) ItemVals(core BCore, items _dafny.Sequence, h Hist) Option {
	if (_dafny.IntOfUint32((items).Cardinality())).Sign() == 0 {
		return Companion_Option_.Create_Some_(_dafny.SeqOf())
	} else {
		var _source0 Option = Companion_Default___.EvalT((core).Dtor_value(), (items).Select(0).(Act), h)
		_ = _source0
		{
			if _source0.Is_Some() {
				var v0 V = _source0.Get_().(Option_Some).V.(V)
				_ = v0
				if v0.Is_VQ() {
					var _0_q Q = v0.Get_().(V_VQ).Q
					_ = _0_q
					if !((_0_q).Dtor_u()).Equals(((core).Dtor_cap()).Dtor_u()) {
						return Companion_Option_.Create_None_()
					} else {
						var _source1 Option = Companion_Default___.ItemVals(core, (items).Drop(1), h)
						_ = _source1
						{
							if _source1.Is_Some() {
								var _1_r _dafny.Sequence = _source1.Get_().(Option_Some).V.(_dafny.Sequence)
								_ = _1_r
								return Companion_Option_.Create_Some_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf((_0_q).Dtor_n()), _1_r))
							}
						}
						{
							return Companion_Option_.Create_None_()
						}
					}
				}
			}
		}
		{
			return Companion_Option_.Create_None_()
		}
	}
}
func (_static *CompanionStruct_Default___) SumI(xs _dafny.Sequence) _dafny.Int {
	var _0___accumulator _dafny.Int = _dafny.Zero
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return (_dafny.Zero).Plus(_0___accumulator)
	} else {
		_0___accumulator = (_0___accumulator).Plus((xs).Select(0).(_dafny.Int))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) MaxI(xs _dafny.Sequence) _dafny.Int {
	if (_dafny.IntOfUint32((xs).Cardinality())).Cmp(_dafny.One) == 0 {
		return (xs).Select(0).(_dafny.Int)
	} else {
		var _0_m _dafny.Int = Companion_Default___.MaxI((xs).Drop(1))
		_ = _0_m
		if ((xs).Select(0).(_dafny.Int)).Cmp(_0_m) >= 0 {
			return (xs).Select(0).(_dafny.Int)
		} else {
			return _0_m
		}
	}
}
func (_static *CompanionStruct_Default___) KeyVals(core BCore, items _dafny.Sequence) Option {
	if (_dafny.IntOfUint32((items).Cardinality())).Sign() == 0 {
		return Companion_Option_.Create_Some_(_dafny.SeqOf())
	} else if !(((items).Select(0).(Act)).Dtor_params()).Contains((core).Dtor_key()) {
		return Companion_Option_.Create_None_()
	} else {
		var _source0 Option = Companion_Default___.KeyVals(core, (items).Drop(1))
		_ = _source0
		{
			if _source0.Is_Some() {
				var _0_r _dafny.Sequence = _source0.Get_().(Option_Some).V.(_dafny.Sequence)
				_ = _0_r
				return Companion_Option_.Create_Some_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf((((items).Select(0).(Act)).Dtor_params()).Get((core).Dtor_key()).(V)), _0_r))
			}
		}
		{
			return Companion_Option_.Create_None_()
		}
	}
}
func (_static *CompanionStruct_Default___) Dedup(vs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((vs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else if _dafny.Companion_Sequence_.Contains((vs).Drop(1), (vs).Select(0).(V)) {
		var _in0 _dafny.Sequence = (vs).Drop(1)
		_ = _in0
		vs = _in0
		goto TAIL_CALL_START
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf((vs).Select(0).(V)))
		var _in1 _dafny.Sequence = (vs).Drop(1)
		_ = _in1
		vs = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) Exceeded(core BCore, items _dafny.Sequence, h Hist) _dafny.Int {
	var _source0 Agg = (core).Dtor_agg()
	_ = _source0
	{
		if _source0.Is_ACount() {
			return Companion_Default___.B2T((_dafny.IntOfUint32((items).Cardinality())).Cmp(((core).Dtor_cap()).Dtor_n()) > 0)
		}
	}
	{
		if _source0.Is_ASum() {
			var _source1 Option = Companion_Default___.ItemVals(core, items, h)
			_ = _source1
			{
				if _source1.Is_Some() {
					var _0_xs _dafny.Sequence = _source1.Get_().(Option_Some).V.(_dafny.Sequence)
					_ = _0_xs
					return Companion_Default___.B2T((Companion_Default___.SumI(_0_xs)).Cmp(((core).Dtor_cap()).Dtor_n()) > 0)
				}
			}
			{
				return Companion_Default___.KU()
			}
		}
	}
	{
		if _source0.Is_AMax() {
			var _source2 Option = Companion_Default___.ItemVals(core, items, h)
			_ = _source2
			{
				if _source2.Is_Some() {
					var _1_xs _dafny.Sequence = _source2.Get_().(Option_Some).V.(_dafny.Sequence)
					_ = _1_xs
					if (_dafny.IntOfUint32((_1_xs).Cardinality())).Sign() == 0 {
						return Companion_Default___.KU()
					} else {
						return Companion_Default___.B2T((Companion_Default___.MaxI(_1_xs)).Cmp(((core).Dtor_cap()).Dtor_n()) > 0)
					}
				}
			}
			{
				return Companion_Default___.KU()
			}
		}
	}
	{
		var _source3 Option = Companion_Default___.KeyVals(core, items)
		_ = _source3
		{
			if _source3.Is_Some() {
				var _2_vs _dafny.Sequence = _source3.Get_().(Option_Some).V.(_dafny.Sequence)
				_ = _2_vs
				return Companion_Default___.B2T((_dafny.IntOfUint32((Companion_Default___.Dedup(_2_vs)).Cardinality())).Cmp(((core).Dtor_cap()).Dtor_n()) > 0)
			}
		}
		{
			return Companion_Default___.KU()
		}
	}
}
func (_static *CompanionStruct_Default___) BoundStat(core BCore, s LSel, a Act, h Hist) _dafny.Int {
	var _0_e _dafny.Int = Companion_Default___.Exceeded(core, Companion_Default___.SelItems(core, s, (h).Dtor_adms(), a), h)
	_ = _0_e
	if (_0_e).Cmp(Companion_Default___.KT()) == 0 {
		var _source0 OnExceed = (core).Dtor_onExceed()
		_ = _source0
		{
			if _source0.Is_OnDeny() {
				return Companion_Default___.Deny()
			}
		}
		{
			return Companion_Default___.Escalate()
		}
	} else if (_0_e).Cmp(Companion_Default___.KU()) == 0 {
		return Companion_Default___.Escalate()
	} else {
		return Companion_Default___.Allow()
	}
}
func (_static *CompanionStruct_Default___) ValidityDec(v Validity, dg Delegation, a Act, h Hist) _dafny.Int {
	if (((a).Dtor_t()).Cmp((v).Dtor_notBefore()) < 0) || (((a).Dtor_t()).Cmp((v).Dtor_notAfter()) > 0) {
		return Companion_Default___.Deny()
	} else if ((((v).Dtor_maxIdle()).Sign() == 1) && (((h).Dtor_last()).Sign() != -1)) && ((((a).Dtor_t()).Minus((h).Dtor_last())).Cmp((v).Dtor_maxIdle()) > 0) {
		return Companion_Default___.Deny()
	} else if (((a).Dtor_depth()).Sign() == -1) || (((a).Dtor_depth()).Cmp((dg).Dtor_maxDepth()) > 0) {
		return Companion_Default___.Deny()
	} else {
		return Companion_Default___.Allow()
	}
}
func (_static *CompanionStruct_Default___) DelegOk(dg Delegation, gid _dafny.Sequence, a Act) bool {
	return (((a).Dtor_depth()).Sign() == 0) || (_dafny.Companion_Sequence_.Contains((dg).Dtor_mayTouch(), gid))
}
func (_static *CompanionStruct_Default___) ProhOne(verbs _dafny.Sequence, res ResPat, c Cond, a Act, h Hist) _dafny.Int {
	var _0_m _dafny.Int = Companion_Default___.AndK(Companion_Default___.B2T(_dafny.Companion_Sequence_.Contains(verbs, (a).Dtor_verb())), Companion_Default___.AndK(Companion_Default___.B2T(Companion_Default___.ResOk(res, (a).Dtor_res())), Companion_Default___.EvalC(c, a, h)))
	_ = _0_m
	if (_0_m).Cmp(Companion_Default___.KT()) == 0 {
		return Companion_Default___.Deny()
	} else if (_0_m).Cmp(Companion_Default___.KU()) == 0 {
		return Companion_Default___.Escalate()
	} else {
		return Companion_Default___.Allow()
	}
}
func (_static *CompanionStruct_Default___) ProhDecG(ont Ontology, ps _dafny.Sequence, a Act, h Hist) _dafny.Int {
	if (_dafny.IntOfUint32((ps).Cardinality())).Sign() == 0 {
		return Companion_Default___.Allow()
	} else {
		return Companion_Default___.MeetD(Companion_Default___.ProhOne(Companion_Default___.ProhVerbs(ont, ((ps).Select(0).(Prohibit)).Dtor_target()), Companion_Default___.ResolveSel(ont, ((ps).Select(0).(Prohibit)).Dtor_res()), ((ps).Select(0).(Prohibit)).Dtor_cond(), a, h), Companion_Default___.ProhDecG(ont, (ps).Drop(1), a, h))
	}
}
func (_static *CompanionStruct_Default___) EscOne(m _dafny.Int) _dafny.Int {
	if (m).Cmp(Companion_Default___.KF()) == 0 {
		return Companion_Default___.Allow()
	} else {
		return Companion_Default___.Escalate()
	}
}
func (_static *CompanionStruct_Default___) EscDecG(cs _dafny.Sequence, a Act, h Hist) _dafny.Int {
	if (_dafny.IntOfUint32((cs).Cardinality())).Sign() == 0 {
		return Companion_Default___.Allow()
	} else {
		return Companion_Default___.MeetD(Companion_Default___.EscOne(Companion_Default___.EvalC((cs).Select(0).(Cond), a, h)), Companion_Default___.EscDecG((cs).Drop(1), a, h))
	}
}
func (_static *CompanionStruct_Default___) BoundsDecG(ont Ontology, bs _dafny.Sequence, gid _dafny.Sequence, a Act, h Hist) _dafny.Int {
	if (_dafny.IntOfUint32((bs).Cardinality())).Sign() == 0 {
		return Companion_Default___.Allow()
	} else {
		var _0_s LSel = Companion_Default___.ResolveBSel(ont, ((bs).Select(0).(Bound)).Dtor_sel())
		_ = _0_s
		return Companion_Default___.MeetD((func() _dafny.Int {
			if Companion_Default___.AppliesL(_0_s, gid, (a).Dtor_verb()) {
				return Companion_Default___.BoundStat(((bs).Select(0).(Bound)).Dtor_core(), _0_s, a, h)
			}
			return Companion_Default___.Allow()
		})(), Companion_Default___.BoundsDecG(ont, (bs).Drop(1), gid, a, h))
	}
}
func (_static *CompanionStruct_Default___) GrantMatch(ont Ontology, g Grant, dg Delegation, a Act, h Hist) _dafny.Int {
	return Companion_Default___.AndK(Companion_Default___.B2T((_dafny.Companion_Sequence_.Equal((a).Dtor_verb(), (g).Dtor_verb())) && (Companion_Default___.DelegOk(dg, (g).Dtor_gid(), a))), Companion_Default___.AndK(Companion_Default___.B2T(Companion_Default___.ResOk(Companion_Default___.ResolveSel(ont, (g).Dtor_res()), (a).Dtor_res())), Companion_Default___.EvalC((g).Dtor_cond(), a, h)))
}
func (_static *CompanionStruct_Default___) GrantDecG(ont Ontology, g Goal, gr Grant, a Act, h Hist) _dafny.Int {
	return Companion_Default___.MeetD(Companion_Default___.DecOfTri(Companion_Default___.GrantMatch(ont, gr, (g).Dtor_deleg(), a, h)), Companion_Default___.BoundsDecG(ont, (g).Dtor_bounds(), (gr).Dtor_gid(), a, h))
}
func (_static *CompanionStruct_Default___) GrantsDecG(ont Ontology, g Goal, gs _dafny.Sequence, a Act, h Hist) _dafny.Int {
	if (_dafny.IntOfUint32((gs).Cardinality())).Sign() == 0 {
		return Companion_Default___.Deny()
	} else {
		return Companion_Default___.JoinD(Companion_Default___.GrantDecG(ont, g, (gs).Select(0).(Grant), a, h), Companion_Default___.GrantsDecG(ont, g, (gs).Drop(1), a, h))
	}
}
func (_static *CompanionStruct_Default___) DG(ont Ontology, g Goal, a Act, h Hist) _dafny.Int {
	return Companion_Default___.MeetD(Companion_Default___.ValidityDec((g).Dtor_validity(), (g).Dtor_deleg(), a, h), Companion_Default___.MeetD(Companion_Default___.ProhDecG(ont, (g).Dtor_prohibits(), a, h), Companion_Default___.MeetD(Companion_Default___.EscDecG((g).Dtor_escalateOn(), a, h), Companion_Default___.GrantsDecG(ont, g, (g).Dtor_grants(), a, h))))
}
func (_static *CompanionStruct_Default___) StrLt(a _dafny.Sequence, b _dafny.Sequence) bool {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((b).Cardinality())).Sign() == 0 {
		return false
	} else if (_dafny.IntOfUint32((a).Cardinality())).Sign() == 0 {
		return true
	} else if ((a).Select(0).(_dafny.CodePoint)) != ((b).Select(0).(_dafny.CodePoint)) /* dircomp */ {
		return (_dafny.IntOfInt32(rune((a).Select(0).(_dafny.CodePoint)))).Cmp(_dafny.IntOfInt32(rune((b).Select(0).(_dafny.CodePoint)))) < 0
	} else {
		var _in0 _dafny.Sequence = (a).Drop(1)
		_ = _in0
		var _in1 _dafny.Sequence = (b).Drop(1)
		_ = _in1
		a = _in0
		b = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) StrictlySorted(xs _dafny.Sequence) bool {
	return ((_dafny.IntOfUint32((xs).Cardinality())).Cmp(_dafny.One) <= 0) || ((Companion_Default___.StrLt((xs).Select(0).(_dafny.Sequence), (xs).Select(1).(_dafny.Sequence))) && (Companion_Default___.StrictlySorted((xs).Drop(1))))
}
func (_static *CompanionStruct_Default___) UnitOk(u Unit) bool {
	var _source0 Unit = u
	_ = _source0
	{
		if _source0.Is_UMoney() {
			var _0_c _dafny.Sequence = _source0.Get_().(Unit_UMoney).Ccy
			_ = _0_c
			return (_dafny.IntOfUint32((_0_c).Cardinality())).Sign() == 1
		}
	}
	{
		return true
	}
}
func (_static *CompanionStruct_Default___) TyOk(t Ty) bool {
	var _source0 Ty = t
	_ = _source0
	{
		if _source0.Is_TyQ() {
			var _0_u Unit = _source0.Get_().(Ty_TyQ).U
			_ = _0_u
			return Companion_Default___.UnitOk(_0_u)
		}
	}
	{
		return true
	}
}
func (_static *CompanionStruct_Default___) VOk(v V) bool {
	var _source0 V = v
	_ = _source0
	{
		if _source0.Is_VQ() {
			var _0_q Q = _source0.Get_().(V_VQ).Q
			_ = _0_q
			return Companion_Default___.UnitOk((_0_q).Dtor_u())
		}
	}
	{
		if _source0.Is_VS() {
			return true
		}
	}
	{
		var _1_items _dafny.Sequence = _source0.Get_().(V_VSet).Items
		_ = _1_items
		return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((_1_items).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
			var _2_i _dafny.Int
			_2_i = interface{}(_forall_var_0).(_dafny.Int)
			return !(((_2_i).Sign() != -1) && ((_2_i).Cmp(_dafny.IntOfUint32((_1_items).Cardinality())) < 0)) || (func() bool {
				var _source1 Atom = (_1_items).Select((_2_i).Uint32()).(Atom)
				_ = _source1
				{
					if _source1.Is_AQ() {
						var _3_q Q = _source1.Get_().(Atom_AQ).Q
						_ = _3_q
						return Companion_Default___.UnitOk((_3_q).Dtor_u())
					}
				}
				{
					return true
				}
			}())
		})
	}
}
func (_static *CompanionStruct_Default___) TypeOfTerm(t Term) Option {
	var _source0 Term = t
	_ = _source0
	{
		if _source0.Is_Param() {
			var _0_ty Ty = _source0.Get_().(Term_Param).Ty
			_ = _0_ty
			return Companion_Option_.Create_Some_(_0_ty)
		}
	}
	{
		if _source0.Is_Lit() {
			var _1_v V = _source0.Get_().(Term_Lit).V
			_ = _1_v
			return Companion_Default___.TypeOfV(_1_v)
		}
	}
	{
		var _2_u Unit = _source0.Get_().(Term_HistAgg).U
		_ = _2_u
		return Companion_Option_.Create_Some_(Companion_Ty_.Create_TyQ_(_2_u))
	}
}
func (_static *CompanionStruct_Default___) TermOk(t Term) bool {
	var _source0 Term = t
	_ = _source0
	{
		if _source0.Is_Param() {
			var _0_p _dafny.Sequence = _source0.Get_().(Term_Param).Path
			_ = _0_p
			var _1_ty Ty = _source0.Get_().(Term_Param).Ty
			_ = _1_ty
			return ((_dafny.IntOfUint32((_0_p).Cardinality())).Sign() == 1) && (Companion_Default___.TyOk(_1_ty))
		}
	}
	{
		if _source0.Is_Lit() {
			var _2_v V = _source0.Get_().(Term_Lit).V
			_ = _2_v
			return Companion_Default___.VOk(_2_v)
		}
	}
	{
		var _3_b _dafny.Sequence = _source0.Get_().(Term_HistAgg).Bid
		_ = _3_b
		var _4_u Unit = _source0.Get_().(Term_HistAgg).U
		_ = _4_u
		return ((_dafny.IntOfUint32((_3_b).Cardinality())).Sign() == 1) && (Companion_Default___.UnitOk(_4_u))
	}
}
func (_static *CompanionStruct_Default___) AllOfTy(items _dafny.Sequence, ty Ty) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((items).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((items).Cardinality())) < 0)) || ((Companion_Default___.TypeOfV(Companion_Default___.AtomV((items).Select((_0_i).Uint32()).(Atom)))).Equals(Companion_Option_.Create_Some_(ty)))
	})
}
func (_static *CompanionStruct_Default___) CmpTyped(op Op, l Term, r Term) bool {
	return (((Companion_Default___.TermOk(l)) && (Companion_Default___.TermOk(r))) && ((Companion_Default___.TypeOfTerm(l)).Is_Some())) && (func() bool {
		var _source0 Op = op
		_ = _source0
		{
			if _source0.Is_Eq() {
				return (Companion_Default___.TypeOfTerm(l)).Equals(Companion_Default___.TypeOfTerm(r))
			}
		}
		{
			if _source0.Is_Ne() {
				return (Companion_Default___.TypeOfTerm(l)).Equals(Companion_Default___.TypeOfTerm(r))
			}
		}
		{
			if _source0.Is_Lt() {
				return ((Companion_Default___.TypeOfTerm(l)).Equals(Companion_Default___.TypeOfTerm(r))) && (((Companion_Default___.TypeOfTerm(l)).Dtor_v().(Ty)).Is_TyQ())
			}
		}
		{
			if _source0.Is_Lte() {
				return ((Companion_Default___.TypeOfTerm(l)).Equals(Companion_Default___.TypeOfTerm(r))) && (((Companion_Default___.TypeOfTerm(l)).Dtor_v().(Ty)).Is_TyQ())
			}
		}
		{
			if _source0.Is_Gt() {
				return ((Companion_Default___.TypeOfTerm(l)).Equals(Companion_Default___.TypeOfTerm(r))) && (((Companion_Default___.TypeOfTerm(l)).Dtor_v().(Ty)).Is_TyQ())
			}
		}
		{
			if _source0.Is_Gte() {
				return ((Companion_Default___.TypeOfTerm(l)).Equals(Companion_Default___.TypeOfTerm(r))) && (((Companion_Default___.TypeOfTerm(l)).Dtor_v().(Ty)).Is_TyQ())
			}
		}
		{
			if _source0.Is_In() {
				return (((r).Is_Lit()) && (((r).Dtor_v()).Is_VSet())) && (Companion_Default___.AllOfTy(((r).Dtor_v()).Dtor_items(), (Companion_Default___.TypeOfTerm(l)).Dtor_v().(Ty)))
			}
		}
		{
			return (((r).Is_Lit()) && (((r).Dtor_v()).Is_VSet())) && (Companion_Default___.AllOfTy(((r).Dtor_v()).Dtor_items(), (Companion_Default___.TypeOfTerm(l)).Dtor_v().(Ty)))
		}
	}())
}
func (_static *CompanionStruct_Default___) CondTyped(c Cond, ok func(_dafny.Sequence, Ty) bool) bool {
	var _source0 Cond = c
	_ = _source0
	{
		if _source0.Is_CTrue() {
			return true
		}
	}
	{
		if _source0.Is_Cmp() {
			var _0_op Op = _source0.Get_().(Cond_Cmp).Op
			_ = _0_op
			var _1_l Term = _source0.Get_().(Cond_Cmp).L
			_ = _1_l
			var _2_r Term = _source0.Get_().(Cond_Cmp).R
			_ = _2_r
			return ((Companion_Default___.CmpTyped(_0_op, _1_l, _2_r)) && (Companion_Default___.ParamsOk(_1_l, ok))) && (Companion_Default___.ParamsOk(_2_r, ok))
		}
	}
	{
		if _source0.Is_And() {
			var _3_x Cond = _source0.Get_().(Cond_And).A
			_ = _3_x
			var _4_y Cond = _source0.Get_().(Cond_And).B
			_ = _4_y
			return (Companion_Default___.CondTyped(_3_x, ok)) && (Companion_Default___.CondTyped(_4_y, ok))
		}
	}
	{
		if _source0.Is_Or() {
			var _5_x Cond = _source0.Get_().(Cond_Or).A
			_ = _5_x
			var _6_y Cond = _source0.Get_().(Cond_Or).B
			_ = _6_y
			return (Companion_Default___.CondTyped(_5_x, ok)) && (Companion_Default___.CondTyped(_6_y, ok))
		}
	}
	{
		var _7_x Cond = _source0.Get_().(Cond_Not).C
		_ = _7_x
		return Companion_Default___.CondTyped(_7_x, ok)
	}
}
func (_static *CompanionStruct_Default___) ParamsOk(t Term, ok func(_dafny.Sequence, Ty) bool) bool {
	var _source0 Term = t
	_ = _source0
	{
		if _source0.Is_Param() {
			var _0_p _dafny.Sequence = _source0.Get_().(Term_Param).Path
			_ = _0_p
			var _1_ty Ty = _source0.Get_().(Term_Param).Ty
			_ = _1_ty
			return (ok)(_0_p, _1_ty)
		}
	}
	{
		return true
	}
}
func (_static *CompanionStruct_Default___) FindDecl(vs _dafny.Sequence, verb _dafny.Sequence) Option {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((vs).Cardinality())).Sign() == 0 {
		return Companion_Option_.Create_None_()
	} else if _dafny.Companion_Sequence_.Equal(((vs).Select(0).(VerbDecl)).Dtor_verb(), verb) {
		return Companion_Option_.Create_Some_((vs).Select(0).(VerbDecl))
	} else {
		var _in0 _dafny.Sequence = (vs).Drop(1)
		_ = _in0
		var _in1 _dafny.Sequence = verb
		_ = _in1
		vs = _in0
		verb = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) HasParam(ps _dafny.Sequence, p _dafny.Sequence, ty Ty) bool {
	return _dafny.Companion_Sequence_.Contains(ps, Companion_ParamDecl_.Create_ParamDecl_(p, ty))
}
func (_static *CompanionStruct_Default___) DeclaredFor(ont Ontology, verbs _dafny.Sequence, p _dafny.Sequence, ty Ty) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((verbs).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((verbs).Cardinality())) < 0)) || (((Companion_Default___.FindDecl((ont).Dtor_verbs(), (verbs).Select((_0_i).Uint32()).(_dafny.Sequence))).Is_Some()) && (Companion_Default___.HasParam(((Companion_Default___.FindDecl((ont).Dtor_verbs(), (verbs).Select((_0_i).Uint32()).(_dafny.Sequence))).Dtor_v().(VerbDecl)).Dtor_params(), p, ty)))
	})
}
func (_static *CompanionStruct_Default___) NoConflictP(ps _dafny.Sequence, p _dafny.Sequence, ty Ty) bool {
	return ((_dafny.IntOfUint32((ps).Cardinality())).Sign() == 0) || (((!_dafny.Companion_Sequence_.Equal(((ps).Select(0).(ParamDecl)).Dtor_path(), p)) || ((((ps).Select(0).(ParamDecl)).Dtor_ty()).Equals(ty))) && (Companion_Default___.NoConflictP((ps).Drop(1), p, ty)))
}
func (_static *CompanionStruct_Default___) NoConflict(vs _dafny.Sequence, p _dafny.Sequence, ty Ty) bool {
	return ((_dafny.IntOfUint32((vs).Cardinality())).Sign() == 0) || ((Companion_Default___.NoConflictP(((vs).Select(0).(VerbDecl)).Dtor_params(), p, ty)) && (Companion_Default___.NoConflict((vs).Drop(1), p, ty)))
}
func (_static *CompanionStruct_Default___) ResSelOk(ont Ontology, s ResSel) bool {
	var _source0 ResSel = s
	_ = _source0
	{
		if _source0.Is_Exact() {
			var _0_id _dafny.Sequence = _source0.Get_().(ResSel_Exact).Id
			_ = _0_id
			return (_dafny.IntOfUint32((_0_id).Cardinality())).Sign() == 1
		}
	}
	{
		if _source0.Is_OneOf() {
			var _1_ids _dafny.Sequence = _source0.Get_().(ResSel_OneOf).Ids
			_ = _1_ids
			return (_dafny.IntOfUint32((_1_ids).Cardinality())).Sign() == 1
		}
	}
	{
		if _source0.Is_Related() {
			var _2_rel _dafny.Sequence = _source0.Get_().(ResSel_Related).Rel
			_ = _2_rel
			var _3_anchor _dafny.Sequence = _source0.Get_().(ResSel_Related).Anchor
			_ = _3_anchor
			return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((ont).Dtor_rels()).Cardinality())), false, func(_exists_var_0 _dafny.Int) bool {
				var _4_i _dafny.Int
				_4_i = interface{}(_exists_var_0).(_dafny.Int)
				return ((((_4_i).Sign() != -1) && ((_4_i).Cmp(_dafny.IntOfUint32(((ont).Dtor_rels()).Cardinality())) < 0)) && (_dafny.Companion_Sequence_.Equal((((ont).Dtor_rels()).Select((_4_i).Uint32()).(RelDecl)).Dtor_rel(), _2_rel))) && (_dafny.Companion_Sequence_.Equal((((ont).Dtor_rels()).Select((_4_i).Uint32()).(RelDecl)).Dtor_anchor(), _3_anchor))
			})
		}
	}
	{
		if _source0.Is_AnyRes() {
			return true
		}
	}
	{
		var _5_ps _dafny.Sequence = _source0.Get_().(ResSel_AllOf).Parts
		_ = _5_ps
		return ((_dafny.IntOfUint32((_5_ps).Cardinality())).Cmp(_dafny.IntOfInt64(2)) >= 0) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((_5_ps).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
			var _6_i _dafny.Int
			_6_i = interface{}(_forall_var_0).(_dafny.Int)
			return !(((_6_i).Sign() != -1) && ((_6_i).Cmp(_dafny.IntOfUint32((_5_ps).Cardinality())) < 0)) || (Companion_Default___.PartOk(ont, (_5_ps).Select((_6_i).Uint32()).(ResPart)))
		}))
	}
}
func (_static *CompanionStruct_Default___) PartOk(ont Ontology, p ResPart) bool {
	var _source0 ResPart = p
	_ = _source0
	{
		if _source0.Is_PartExact() {
			var _0_id _dafny.Sequence = _source0.Get_().(ResPart_PartExact).Id
			_ = _0_id
			return (_dafny.IntOfUint32((_0_id).Cardinality())).Sign() == 1
		}
	}
	{
		if _source0.Is_PartOneOf() {
			var _1_ids _dafny.Sequence = _source0.Get_().(ResPart_PartOneOf).Ids
			_ = _1_ids
			return (_dafny.IntOfUint32((_1_ids).Cardinality())).Sign() == 1
		}
	}
	{
		var _2_rel _dafny.Sequence = _source0.Get_().(ResPart_PartRelated).Rel
		_ = _2_rel
		var _3_anchor _dafny.Sequence = _source0.Get_().(ResPart_PartRelated).Anchor
		_ = _3_anchor
		return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((ont).Dtor_rels()).Cardinality())), false, func(_exists_var_0 _dafny.Int) bool {
			var _4_i _dafny.Int
			_4_i = interface{}(_exists_var_0).(_dafny.Int)
			return ((((_4_i).Sign() != -1) && ((_4_i).Cmp(_dafny.IntOfUint32(((ont).Dtor_rels()).Cardinality())) < 0)) && (_dafny.Companion_Sequence_.Equal((((ont).Dtor_rels()).Select((_4_i).Uint32()).(RelDecl)).Dtor_rel(), _2_rel))) && (_dafny.Companion_Sequence_.Equal((((ont).Dtor_rels()).Select((_4_i).Uint32()).(RelDecl)).Dtor_anchor(), _3_anchor))
		})
	}
}
func (_static *CompanionStruct_Default___) GrantOk(ont Ontology, g Goal, gr Grant) bool {
	return (((((_dafny.IntOfUint32(((gr).Dtor_gid()).Cardinality())).Sign() == 1) && ((Companion_Default___.FindDecl((ont).Dtor_verbs(), (gr).Dtor_verb())).Is_Some())) && (Companion_Default___.ResSelOk(ont, (gr).Dtor_res()))) && (!(((gr).Dtor_res()).Is_AnyRes()) || (_dafny.Companion_Sequence_.Contains((g).Dtor_wildcardAck(), (gr).Dtor_gid())))) && (Companion_Default___.CondTyped((gr).Dtor_cond(), (func(_0_ont Ontology, _1_gr Grant) func(_dafny.Sequence, Ty) bool {
		return func(_2_p _dafny.Sequence, _3_ty Ty) bool {
			return Companion_Default___.DeclaredFor(_0_ont, _dafny.SeqOf((_1_gr).Dtor_verb()), _2_p, _3_ty)
		}
	})(ont, gr)))
}
func (_static *CompanionStruct_Default___) ProhibitOk(ont Ontology, p Prohibit) bool {
	return ((((_dafny.IntOfUint32(((p).Dtor_pid()).Cardinality())).Sign() == 1) && (Companion_Default___.ResSelOk(ont, (p).Dtor_res()))) && (func() bool {
		var _source0 ProhTarget = (p).Dtor_target()
		_ = _source0
		{
			if _source0.Is_PVerb() {
				var _0_v _dafny.Sequence = _source0.Get_().(ProhTarget_PVerb).Verb
				_ = _0_v
				return (Companion_Default___.FindDecl((ont).Dtor_verbs(), _0_v)).Is_Some()
			}
		}
		{
			var _1_c _dafny.Sequence = _source0.Get_().(ProhTarget_PEffect).Cls
			_ = _1_c
			return ((_dafny.IntOfUint32((_1_c).Cardinality())).Sign() == 1) && ((_dafny.IntOfUint32((Companion_Default___.VerbsOfClass((ont).Dtor_verbs(), _1_c)).Cardinality())).Sign() == 1)
		}
	}())) && (Companion_Default___.CondTyped((p).Dtor_cond(), (func(_2_ont Ontology, _3_p Prohibit) func(_dafny.Sequence, Ty) bool {
		return func(_4_q _dafny.Sequence, _5_ty Ty) bool {
			return Companion_Default___.DeclaredFor(_2_ont, Companion_Default___.ProhVerbs(_2_ont, (_3_p).Dtor_target()), _4_q, _5_ty)
		}
	})(ont, p)))
}
func (_static *CompanionStruct_Default___) WindowOk(w Window) bool {
	var _source0 Window = w
	_ = _source0
	{
		if _source0.Is_WSliding() {
			var _0_ms _dafny.Int = _source0.Get_().(Window_WSliding).Ms
			_ = _0_ms
			return (_0_ms).Sign() == 1
		}
	}
	{
		if _source0.Is_WPeriod() {
			var _1_ms _dafny.Int = _source0.Get_().(Window_WPeriod).Ms
			_ = _1_ms
			return (_1_ms).Sign() == 1
		}
	}
	{
		return true
	}
}
func (_static *CompanionStruct_Default___) ScopeOk(s Scope) bool {
	var _source0 Scope = s
	_ = _source0
	{
		if _source0.Is_SFleet() {
			var _0_ag _dafny.Sequence = _source0.Get_().(Scope_SFleet).Agents
			_ = _0_ag
			return (_dafny.IntOfUint32((_0_ag).Cardinality())).Sign() == 1
		}
	}
	{
		return true
	}
}
func (_static *CompanionStruct_Default___) BoundOk(ont Ontology, g Goal, b Bound) bool {
	return ((((((((_dafny.IntOfUint32(((b).Dtor_bid()).Cardinality())).Sign() == 1) && (Companion_Default___.TermOk(((b).Dtor_core()).Dtor_value()))) && (Companion_Default___.UnitOk((((b).Dtor_core()).Dtor_cap()).Dtor_u()))) && (((((b).Dtor_core()).Dtor_cap()).Dtor_n()).Sign() != -1)) && (Companion_Default___.WindowOk(((b).Dtor_core()).Dtor_window()))) && (Companion_Default___.ScopeOk(((b).Dtor_core()).Dtor_scope()))) && (func() bool {
		var _source0 Sel = (b).Dtor_sel()
		_ = _source0
		{
			if _source0.Is_SelGids() {
				var _0_gids _dafny.Sequence = _source0.Get_().(Sel_SelGids).Gids
				_ = _0_gids
				return ((_dafny.IntOfUint32((_0_gids).Cardinality())).Sign() == 1) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((_0_gids).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
					var _1_i _dafny.Int
					_1_i = interface{}(_forall_var_0).(_dafny.Int)
					return !(((_1_i).Sign() != -1) && ((_1_i).Cmp(_dafny.IntOfUint32((_0_gids).Cardinality())) < 0)) || (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g).Dtor_grants()).Cardinality())), false, func(_exists_var_0 _dafny.Int) bool {
						var _2_j _dafny.Int
						_2_j = interface{}(_exists_var_0).(_dafny.Int)
						return (((_2_j).Sign() != -1) && ((_2_j).Cmp(_dafny.IntOfUint32(((g).Dtor_grants()).Cardinality())) < 0)) && (_dafny.Companion_Sequence_.Equal((((g).Dtor_grants()).Select((_2_j).Uint32()).(Grant)).Dtor_gid(), (_0_gids).Select((_1_i).Uint32()).(_dafny.Sequence)))
					}))
				}))
			}
		}
		{
			var _3_c _dafny.Sequence = _source0.Get_().(Sel_SelEffect).Cls
			_ = _3_c
			return (_dafny.IntOfUint32((_3_c).Cardinality())).Sign() == 1
		}
	}())) && (func() bool {
		var _source1 Agg = ((b).Dtor_core()).Dtor_agg()
		_ = _source1
		{
			if _source1.Is_ACount() {
				return ((((b).Dtor_core()).Dtor_cap()).Dtor_u()).Equals(Companion_Unit_.Create_UCount_())
			}
		}
		{
			if _source1.Is_ASum() {
				return (Companion_Default___.TypeOfTerm(((b).Dtor_core()).Dtor_value())).Equals(Companion_Option_.Create_Some_(Companion_Ty_.Create_TyQ_((((b).Dtor_core()).Dtor_cap()).Dtor_u())))
			}
		}
		{
			if _source1.Is_AMax() {
				return (Companion_Default___.TypeOfTerm(((b).Dtor_core()).Dtor_value())).Equals(Companion_Option_.Create_Some_(Companion_Ty_.Create_TyQ_((((b).Dtor_core()).Dtor_cap()).Dtor_u())))
			}
		}
		{
			return (((((b).Dtor_core()).Dtor_cap()).Dtor_u()).Equals(Companion_Unit_.Create_UCount_())) && ((_dafny.IntOfUint32((((b).Dtor_core()).Dtor_key()).Cardinality())).Sign() == 1)
		}
	}())
}
func (_static *CompanionStruct_Default___) ValidityOk(v Validity, dg Delegation, g Goal) bool {
	return ((((((v).Dtor_notBefore()).Cmp((v).Dtor_notAfter()) <= 0) && (((v).Dtor_maxIdle()).Sign() != -1)) && ((((dg).Dtor_maxDepth()).Sign() != -1) && (((dg).Dtor_maxDepth()).Cmp(_dafny.IntOfInt64(16)) <= 0))) && ((dg).Dtor_narrowOnly())) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((dg).Dtor_mayTouch()).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32(((dg).Dtor_mayTouch()).Cardinality())) < 0)) || (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g).Dtor_grants()).Cardinality())), false, func(_exists_var_0 _dafny.Int) bool {
			var _1_j _dafny.Int
			_1_j = interface{}(_exists_var_0).(_dafny.Int)
			return (((_1_j).Sign() != -1) && ((_1_j).Cmp(_dafny.IntOfUint32(((g).Dtor_grants()).Cardinality())) < 0)) && (_dafny.Companion_Sequence_.Equal((((g).Dtor_grants()).Select((_1_j).Uint32()).(Grant)).Dtor_gid(), ((dg).Dtor_mayTouch()).Select((_0_i).Uint32()).(_dafny.Sequence)))
		}))
	}))
}
func (_static *CompanionStruct_Default___) HoleOk(g Goal, h Hole) bool {
	return ((_dafny.IntOfUint32(((h).Dtor_hid()).Cardinality())).Sign() == 1) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((h).Dtor_affects()).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32(((h).Dtor_affects()).Cardinality())) < 0)) || (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g).Dtor_grants()).Cardinality())), false, func(_exists_var_0 _dafny.Int) bool {
			var _1_j _dafny.Int
			_1_j = interface{}(_exists_var_0).(_dafny.Int)
			return (((_1_j).Sign() != -1) && ((_1_j).Cmp(_dafny.IntOfUint32(((g).Dtor_grants()).Cardinality())) < 0)) && (_dafny.Companion_Sequence_.Equal((((g).Dtor_grants()).Select((_1_j).Uint32()).(Grant)).Dtor_gid(), ((h).Dtor_affects()).Select((_0_i).Uint32()).(_dafny.Sequence)))
		}))
	}))
}
func (_static *CompanionStruct_Default___) Gids(gs _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((gs).Cardinality())).Uint32(), func(coer0 func(_dafny.Int) _dafny.Sequence) func(_dafny.Int) interface{} {
		return func(arg0 _dafny.Int) interface{} {
			return coer0(arg0)
		}
	}((func(_0_gs _dafny.Sequence) func(_dafny.Int) _dafny.Sequence {
		return func(_1_i _dafny.Int) _dafny.Sequence {
			return ((_0_gs).Select((_1_i).Uint32()).(Grant)).Dtor_gid()
		}
	})(gs)))
}
func (_static *CompanionStruct_Default___) Pids(ps _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((ps).Cardinality())).Uint32(), func(coer1 func(_dafny.Int) _dafny.Sequence) func(_dafny.Int) interface{} {
		return func(arg1 _dafny.Int) interface{} {
			return coer1(arg1)
		}
	}((func(_0_ps _dafny.Sequence) func(_dafny.Int) _dafny.Sequence {
		return func(_1_i _dafny.Int) _dafny.Sequence {
			return ((_0_ps).Select((_1_i).Uint32()).(Prohibit)).Dtor_pid()
		}
	})(ps)))
}
func (_static *CompanionStruct_Default___) Bids(bs _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((bs).Cardinality())).Uint32(), func(coer2 func(_dafny.Int) _dafny.Sequence) func(_dafny.Int) interface{} {
		return func(arg2 _dafny.Int) interface{} {
			return coer2(arg2)
		}
	}((func(_0_bs _dafny.Sequence) func(_dafny.Int) _dafny.Sequence {
		return func(_1_i _dafny.Int) _dafny.Sequence {
			return ((_0_bs).Select((_1_i).Uint32()).(Bound)).Dtor_bid()
		}
	})(bs)))
}
func (_static *CompanionStruct_Default___) Hids(hs _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((hs).Cardinality())).Uint32(), func(coer3 func(_dafny.Int) _dafny.Sequence) func(_dafny.Int) interface{} {
		return func(arg3 _dafny.Int) interface{} {
			return coer3(arg3)
		}
	}((func(_0_hs _dafny.Sequence) func(_dafny.Int) _dafny.Sequence {
		return func(_1_i _dafny.Int) _dafny.Sequence {
			return ((_0_hs).Select((_1_i).Uint32()).(Hole)).Dtor_hid()
		}
	})(hs)))
}
func (_static *CompanionStruct_Default___) EscsTyped(ont Ontology, g Goal) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g).Dtor_escalateOn()).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32(((g).Dtor_escalateOn()).Cardinality())) < 0)) || (Companion_Default___.CondTyped(((g).Dtor_escalateOn()).Select((_0_i).Uint32()).(Cond), (func(_1_ont Ontology) func(_dafny.Sequence, Ty) bool {
			return func(_2_p _dafny.Sequence, _3_ty Ty) bool {
				return Companion_Default___.NoConflict((_1_ont).Dtor_verbs(), _2_p, _3_ty)
			}
		})(ont)))
	})
}
func (_static *CompanionStruct_Default___) Sorted4(g Goal) bool {
	return (((Companion_Default___.StrictlySorted(Companion_Default___.Gids((g).Dtor_grants()))) && (Companion_Default___.StrictlySorted(Companion_Default___.Pids((g).Dtor_prohibits())))) && (Companion_Default___.StrictlySorted(Companion_Default___.Bids((g).Dtor_bounds())))) && (Companion_Default___.StrictlySorted(Companion_Default___.Hids((g).Dtor_holes())))
}
func (_static *CompanionStruct_Default___) IsWellTyped(ont Ontology, g Goal) bool {
	return ((((((Companion_Default___.Sorted4(g)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g).Dtor_grants()).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32(((g).Dtor_grants()).Cardinality())) < 0)) || (Companion_Default___.GrantOk(ont, g, ((g).Dtor_grants()).Select((_0_i).Uint32()).(Grant)))
	}))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g).Dtor_prohibits()).Cardinality())), true, func(_forall_var_1 _dafny.Int) bool {
		var _1_i _dafny.Int
		_1_i = interface{}(_forall_var_1).(_dafny.Int)
		return !(((_1_i).Sign() != -1) && ((_1_i).Cmp(_dafny.IntOfUint32(((g).Dtor_prohibits()).Cardinality())) < 0)) || (Companion_Default___.ProhibitOk(ont, ((g).Dtor_prohibits()).Select((_1_i).Uint32()).(Prohibit)))
	}))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g).Dtor_bounds()).Cardinality())), true, func(_forall_var_2 _dafny.Int) bool {
		var _2_i _dafny.Int
		_2_i = interface{}(_forall_var_2).(_dafny.Int)
		return !(((_2_i).Sign() != -1) && ((_2_i).Cmp(_dafny.IntOfUint32(((g).Dtor_bounds()).Cardinality())) < 0)) || (Companion_Default___.BoundOk(ont, g, ((g).Dtor_bounds()).Select((_2_i).Uint32()).(Bound)))
	}))) && (Companion_Default___.EscsTyped(ont, g))) && (Companion_Default___.ValidityOk((g).Dtor_validity(), (g).Dtor_deleg(), g))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32(((g).Dtor_holes()).Cardinality())), true, func(_forall_var_3 _dafny.Int) bool {
		var _3_i _dafny.Int
		_3_i = interface{}(_forall_var_3).(_dafny.Int)
		return !(((_3_i).Sign() != -1) && ((_3_i).Cmp(_dafny.IntOfUint32(((g).Dtor_holes()).Cardinality())) < 0)) || (Companion_Default___.HoleOk(g, ((g).Dtor_holes()).Select((_3_i).Uint32()).(Hole)))
	}))
}
func (_static *CompanionStruct_Default___) Signable(ont Ontology, g Goal) bool {
	return (Companion_Default___.IsWellTyped(ont, g)) && ((_dafny.IntOfUint32(((g).Dtor_holes()).Cardinality())).Sign() == 0)
}
func (_static *CompanionStruct_Default___) Deny() _dafny.Int {
	return _dafny.Zero
}
func (_static *CompanionStruct_Default___) Escalate() _dafny.Int {
	return _dafny.One
}
func (_static *CompanionStruct_Default___) Allow() _dafny.Int {
	return _dafny.IntOfInt64(2)
}
func (_static *CompanionStruct_Default___) KF() _dafny.Int {
	return _dafny.Zero
}
func (_static *CompanionStruct_Default___) KU() _dafny.Int {
	return _dafny.One
}
func (_static *CompanionStruct_Default___) KT() _dafny.Int {
	return _dafny.IntOfInt64(2)
}

// End of class Default__

// Definition of class Dec
type Dec struct {
}

func New_Dec_() *Dec {
	_this := Dec{}

	return &_this
}

type CompanionStruct_Dec_ struct {
}

var Companion_Dec_ = CompanionStruct_Dec_{}

func (*Dec) String() string {
	return "GoalIr.Dec"
}

// End of class Dec

func Type_Dec_() _dafny.TypeDescriptor {
	return type_Dec_{}
}

type type_Dec_ struct {
}

func (_this type_Dec_) Default() interface{} {
	return _dafny.Zero
}

func (_this type_Dec_) String() string {
	return "GoalIr.Dec"
}
func (_this *CompanionStruct_Dec_) Is_(__source _dafny.Int) bool {
	var _0_d _dafny.Int = (__source)
	_ = _0_d
	return ((_0_d).Sign() != -1) && ((_0_d).Cmp(_dafny.IntOfInt64(2)) <= 0)
}

// Definition of class Tri
type Tri struct {
}

func New_Tri_() *Tri {
	_this := Tri{}

	return &_this
}

type CompanionStruct_Tri_ struct {
}

var Companion_Tri_ = CompanionStruct_Tri_{}

func (*Tri) String() string {
	return "GoalIr.Tri"
}

// End of class Tri

func Type_Tri_() _dafny.TypeDescriptor {
	return type_Tri_{}
}

type type_Tri_ struct {
}

func (_this type_Tri_) Default() interface{} {
	return _dafny.Zero
}

func (_this type_Tri_) String() string {
	return "GoalIr.Tri"
}
func (_this *CompanionStruct_Tri_) Is_(__source _dafny.Int) bool {
	var _1_t _dafny.Int = (__source)
	_ = _1_t
	return ((_1_t).Sign() != -1) && ((_1_t).Cmp(_dafny.IntOfInt64(2)) <= 0)
}

// Definition of datatype Unit
type Unit struct {
	Data_Unit_
}

func (_this Unit) Get_() Data_Unit_ {
	return _this.Data_Unit_
}

type Data_Unit_ interface {
	isUnit()
}

type CompanionStruct_Unit_ struct {
}

var Companion_Unit_ = CompanionStruct_Unit_{}

type Unit_UMoney struct {
	Ccy _dafny.Sequence
}

func (Unit_UMoney) isUnit() {}

func (CompanionStruct_Unit_) Create_UMoney_(Ccy _dafny.Sequence) Unit {
	return Unit{Unit_UMoney{Ccy}}
}

func (_this Unit) Is_UMoney() bool {
	_, ok := _this.Get_().(Unit_UMoney)
	return ok
}

type Unit_UCount struct {
}

func (Unit_UCount) isUnit() {}

func (CompanionStruct_Unit_) Create_UCount_() Unit {
	return Unit{Unit_UCount{}}
}

func (_this Unit) Is_UCount() bool {
	_, ok := _this.Get_().(Unit_UCount)
	return ok
}

type Unit_UDuration struct {
}

func (Unit_UDuration) isUnit() {}

func (CompanionStruct_Unit_) Create_UDuration_() Unit {
	return Unit{Unit_UDuration{}}
}

func (_this Unit) Is_UDuration() bool {
	_, ok := _this.Get_().(Unit_UDuration)
	return ok
}

type Unit_UInstant struct {
}

func (Unit_UInstant) isUnit() {}

func (CompanionStruct_Unit_) Create_UInstant_() Unit {
	return Unit{Unit_UInstant{}}
}

func (_this Unit) Is_UInstant() bool {
	_, ok := _this.Get_().(Unit_UInstant)
	return ok
}

type Unit_UBytes struct {
}

func (Unit_UBytes) isUnit() {}

func (CompanionStruct_Unit_) Create_UBytes_() Unit {
	return Unit{Unit_UBytes{}}
}

func (_this Unit) Is_UBytes() bool {
	_, ok := _this.Get_().(Unit_UBytes)
	return ok
}

type Unit_URatio struct {
}

func (Unit_URatio) isUnit() {}

func (CompanionStruct_Unit_) Create_URatio_() Unit {
	return Unit{Unit_URatio{}}
}

func (_this Unit) Is_URatio() bool {
	_, ok := _this.Get_().(Unit_URatio)
	return ok
}

func (CompanionStruct_Unit_) Default() Unit {
	return Companion_Unit_.Create_UMoney_(_dafny.EmptySeq)
}

func (_this Unit) Dtor_ccy() _dafny.Sequence {
	return _this.Get_().(Unit_UMoney).Ccy
}

func (_this Unit) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Unit_UMoney:
		{
			return "GoalIr.Unit.UMoney" + "(" + data.Ccy.VerbatimString(true) + ")"
		}
	case Unit_UCount:
		{
			return "GoalIr.Unit.UCount"
		}
	case Unit_UDuration:
		{
			return "GoalIr.Unit.UDuration"
		}
	case Unit_UInstant:
		{
			return "GoalIr.Unit.UInstant"
		}
	case Unit_UBytes:
		{
			return "GoalIr.Unit.UBytes"
		}
	case Unit_URatio:
		{
			return "GoalIr.Unit.URatio"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Unit) Equals(other Unit) bool {
	switch data1 := _this.Get_().(type) {
	case Unit_UMoney:
		{
			data2, ok := other.Get_().(Unit_UMoney)
			return ok && data1.Ccy.Equals(data2.Ccy)
		}
	case Unit_UCount:
		{
			_, ok := other.Get_().(Unit_UCount)
			return ok
		}
	case Unit_UDuration:
		{
			_, ok := other.Get_().(Unit_UDuration)
			return ok
		}
	case Unit_UInstant:
		{
			_, ok := other.Get_().(Unit_UInstant)
			return ok
		}
	case Unit_UBytes:
		{
			_, ok := other.Get_().(Unit_UBytes)
			return ok
		}
	case Unit_URatio:
		{
			_, ok := other.Get_().(Unit_URatio)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Unit) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Unit)
	return ok && _this.Equals(typed)
}

func Type_Unit_() _dafny.TypeDescriptor {
	return type_Unit_{}
}

type type_Unit_ struct {
}

func (_this type_Unit_) Default() interface{} {
	return Companion_Unit_.Default()
}

func (_this type_Unit_) String() string {
	return "GoalIr.Unit"
}
func (_this Unit) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Unit{}

// End of datatype Unit

// Definition of datatype Q
type Q struct {
	Data_Q_
}

func (_this Q) Get_() Data_Q_ {
	return _this.Data_Q_
}

type Data_Q_ interface {
	isQ()
}

type CompanionStruct_Q_ struct {
}

var Companion_Q_ = CompanionStruct_Q_{}

type Q_Q struct {
	U Unit
	N _dafny.Int
}

func (Q_Q) isQ() {}

func (CompanionStruct_Q_) Create_Q_(U Unit, N _dafny.Int) Q {
	return Q{Q_Q{U, N}}
}

func (_this Q) Is_Q() bool {
	_, ok := _this.Get_().(Q_Q)
	return ok
}

func (CompanionStruct_Q_) Default() Q {
	return Companion_Q_.Create_Q_(Companion_Unit_.Default(), _dafny.Zero)
}

func (_this Q) Dtor_u() Unit {
	return _this.Get_().(Q_Q).U
}

func (_this Q) Dtor_n() _dafny.Int {
	return _this.Get_().(Q_Q).N
}

func (_this Q) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Q_Q:
		{
			return "GoalIr.Q.Q" + "(" + _dafny.String(data.U) + ", " + _dafny.String(data.N) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Q) Equals(other Q) bool {
	switch data1 := _this.Get_().(type) {
	case Q_Q:
		{
			data2, ok := other.Get_().(Q_Q)
			return ok && data1.U.Equals(data2.U) && data1.N.Cmp(data2.N) == 0
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Q) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Q)
	return ok && _this.Equals(typed)
}

func Type_Q_() _dafny.TypeDescriptor {
	return type_Q_{}
}

type type_Q_ struct {
}

func (_this type_Q_) Default() interface{} {
	return Companion_Q_.Default()
}

func (_this type_Q_) String() string {
	return "GoalIr.Q"
}
func (_this Q) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Q{}

// End of datatype Q

// Definition of datatype Atom
type Atom struct {
	Data_Atom_
}

func (_this Atom) Get_() Data_Atom_ {
	return _this.Data_Atom_
}

type Data_Atom_ interface {
	isAtom()
}

type CompanionStruct_Atom_ struct {
}

var Companion_Atom_ = CompanionStruct_Atom_{}

type Atom_AQ struct {
	Q Q
}

func (Atom_AQ) isAtom() {}

func (CompanionStruct_Atom_) Create_AQ_(Q Q) Atom {
	return Atom{Atom_AQ{Q}}
}

func (_this Atom) Is_AQ() bool {
	_, ok := _this.Get_().(Atom_AQ)
	return ok
}

type Atom_AS struct {
	S _dafny.Sequence
}

func (Atom_AS) isAtom() {}

func (CompanionStruct_Atom_) Create_AS_(S _dafny.Sequence) Atom {
	return Atom{Atom_AS{S}}
}

func (_this Atom) Is_AS() bool {
	_, ok := _this.Get_().(Atom_AS)
	return ok
}

func (CompanionStruct_Atom_) Default() Atom {
	return Companion_Atom_.Create_AQ_(Companion_Q_.Default())
}

func (_this Atom) Dtor_q() Q {
	return _this.Get_().(Atom_AQ).Q
}

func (_this Atom) Dtor_s() _dafny.Sequence {
	return _this.Get_().(Atom_AS).S
}

func (_this Atom) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Atom_AQ:
		{
			return "GoalIr.Atom.AQ" + "(" + _dafny.String(data.Q) + ")"
		}
	case Atom_AS:
		{
			return "GoalIr.Atom.AS" + "(" + data.S.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Atom) Equals(other Atom) bool {
	switch data1 := _this.Get_().(type) {
	case Atom_AQ:
		{
			data2, ok := other.Get_().(Atom_AQ)
			return ok && data1.Q.Equals(data2.Q)
		}
	case Atom_AS:
		{
			data2, ok := other.Get_().(Atom_AS)
			return ok && data1.S.Equals(data2.S)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Atom) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Atom)
	return ok && _this.Equals(typed)
}

func Type_Atom_() _dafny.TypeDescriptor {
	return type_Atom_{}
}

type type_Atom_ struct {
}

func (_this type_Atom_) Default() interface{} {
	return Companion_Atom_.Default()
}

func (_this type_Atom_) String() string {
	return "GoalIr.Atom"
}
func (_this Atom) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Atom{}

// End of datatype Atom

// Definition of datatype V
type V struct {
	Data_V_
}

func (_this V) Get_() Data_V_ {
	return _this.Data_V_
}

type Data_V_ interface {
	isV()
}

type CompanionStruct_V_ struct {
}

var Companion_V_ = CompanionStruct_V_{}

type V_VQ struct {
	Q Q
}

func (V_VQ) isV() {}

func (CompanionStruct_V_) Create_VQ_(Q Q) V {
	return V{V_VQ{Q}}
}

func (_this V) Is_VQ() bool {
	_, ok := _this.Get_().(V_VQ)
	return ok
}

type V_VS struct {
	S _dafny.Sequence
}

func (V_VS) isV() {}

func (CompanionStruct_V_) Create_VS_(S _dafny.Sequence) V {
	return V{V_VS{S}}
}

func (_this V) Is_VS() bool {
	_, ok := _this.Get_().(V_VS)
	return ok
}

type V_VSet struct {
	Items _dafny.Sequence
}

func (V_VSet) isV() {}

func (CompanionStruct_V_) Create_VSet_(Items _dafny.Sequence) V {
	return V{V_VSet{Items}}
}

func (_this V) Is_VSet() bool {
	_, ok := _this.Get_().(V_VSet)
	return ok
}

func (CompanionStruct_V_) Default() V {
	return Companion_V_.Create_VQ_(Companion_Q_.Default())
}

func (_this V) Dtor_q() Q {
	return _this.Get_().(V_VQ).Q
}

func (_this V) Dtor_s() _dafny.Sequence {
	return _this.Get_().(V_VS).S
}

func (_this V) Dtor_items() _dafny.Sequence {
	return _this.Get_().(V_VSet).Items
}

func (_this V) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case V_VQ:
		{
			return "GoalIr.V.VQ" + "(" + _dafny.String(data.Q) + ")"
		}
	case V_VS:
		{
			return "GoalIr.V.VS" + "(" + data.S.VerbatimString(true) + ")"
		}
	case V_VSet:
		{
			return "GoalIr.V.VSet" + "(" + _dafny.String(data.Items) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this V) Equals(other V) bool {
	switch data1 := _this.Get_().(type) {
	case V_VQ:
		{
			data2, ok := other.Get_().(V_VQ)
			return ok && data1.Q.Equals(data2.Q)
		}
	case V_VS:
		{
			data2, ok := other.Get_().(V_VS)
			return ok && data1.S.Equals(data2.S)
		}
	case V_VSet:
		{
			data2, ok := other.Get_().(V_VSet)
			return ok && data1.Items.Equals(data2.Items)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this V) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(V)
	return ok && _this.Equals(typed)
}

func Type_V_() _dafny.TypeDescriptor {
	return type_V_{}
}

type type_V_ struct {
}

func (_this type_V_) Default() interface{} {
	return Companion_V_.Default()
}

func (_this type_V_) String() string {
	return "GoalIr.V"
}
func (_this V) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = V{}

// End of datatype V

// Definition of datatype Ty
type Ty struct {
	Data_Ty_
}

func (_this Ty) Get_() Data_Ty_ {
	return _this.Data_Ty_
}

type Data_Ty_ interface {
	isTy()
}

type CompanionStruct_Ty_ struct {
}

var Companion_Ty_ = CompanionStruct_Ty_{}

type Ty_TyQ struct {
	U Unit
}

func (Ty_TyQ) isTy() {}

func (CompanionStruct_Ty_) Create_TyQ_(U Unit) Ty {
	return Ty{Ty_TyQ{U}}
}

func (_this Ty) Is_TyQ() bool {
	_, ok := _this.Get_().(Ty_TyQ)
	return ok
}

type Ty_TyS struct {
}

func (Ty_TyS) isTy() {}

func (CompanionStruct_Ty_) Create_TyS_() Ty {
	return Ty{Ty_TyS{}}
}

func (_this Ty) Is_TyS() bool {
	_, ok := _this.Get_().(Ty_TyS)
	return ok
}

func (CompanionStruct_Ty_) Default() Ty {
	return Companion_Ty_.Create_TyQ_(Companion_Unit_.Default())
}

func (_this Ty) Dtor_u() Unit {
	return _this.Get_().(Ty_TyQ).U
}

func (_this Ty) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Ty_TyQ:
		{
			return "GoalIr.Ty.TyQ" + "(" + _dafny.String(data.U) + ")"
		}
	case Ty_TyS:
		{
			return "GoalIr.Ty.TyS"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Ty) Equals(other Ty) bool {
	switch data1 := _this.Get_().(type) {
	case Ty_TyQ:
		{
			data2, ok := other.Get_().(Ty_TyQ)
			return ok && data1.U.Equals(data2.U)
		}
	case Ty_TyS:
		{
			_, ok := other.Get_().(Ty_TyS)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Ty) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Ty)
	return ok && _this.Equals(typed)
}

func Type_Ty_() _dafny.TypeDescriptor {
	return type_Ty_{}
}

type type_Ty_ struct {
}

func (_this type_Ty_) Default() interface{} {
	return Companion_Ty_.Default()
}

func (_this type_Ty_) String() string {
	return "GoalIr.Ty"
}
func (_this Ty) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Ty{}

// End of datatype Ty

// Definition of datatype Option
type Option struct {
	Data_Option_
}

func (_this Option) Get_() Data_Option_ {
	return _this.Data_Option_
}

type Data_Option_ interface {
	isOption()
}

type CompanionStruct_Option_ struct {
}

var Companion_Option_ = CompanionStruct_Option_{}

type Option_None struct {
}

func (Option_None) isOption() {}

func (CompanionStruct_Option_) Create_None_() Option {
	return Option{Option_None{}}
}

func (_this Option) Is_None() bool {
	_, ok := _this.Get_().(Option_None)
	return ok
}

type Option_Some struct {
	V interface{}
}

func (Option_Some) isOption() {}

func (CompanionStruct_Option_) Create_Some_(V interface{}) Option {
	return Option{Option_Some{V}}
}

func (_this Option) Is_Some() bool {
	_, ok := _this.Get_().(Option_Some)
	return ok
}

func (CompanionStruct_Option_) Default() Option {
	return Companion_Option_.Create_None_()
}

func (_this Option) Dtor_v() interface{} {
	return _this.Get_().(Option_Some).V
}

func (_this Option) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Option_None:
		{
			return "GoalIr.Option.None"
		}
	case Option_Some:
		{
			return "GoalIr.Option.Some" + "(" + _dafny.String(data.V) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Option) Equals(other Option) bool {
	switch data1 := _this.Get_().(type) {
	case Option_None:
		{
			_, ok := other.Get_().(Option_None)
			return ok
		}
	case Option_Some:
		{
			data2, ok := other.Get_().(Option_Some)
			return ok && _dafny.AreEqual(data1.V, data2.V)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Option) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Option)
	return ok && _this.Equals(typed)
}

func Type_Option_() _dafny.TypeDescriptor {
	return type_Option_{}
}

type type_Option_ struct {
}

func (_this type_Option_) Default() interface{} {
	return Companion_Option_.Default()
}

func (_this type_Option_) String() string {
	return "GoalIr.Option"
}
func (_this Option) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Option{}

// End of datatype Option

// Definition of datatype Term
type Term struct {
	Data_Term_
}

func (_this Term) Get_() Data_Term_ {
	return _this.Data_Term_
}

type Data_Term_ interface {
	isTerm()
}

type CompanionStruct_Term_ struct {
}

var Companion_Term_ = CompanionStruct_Term_{}

type Term_Param struct {
	Path _dafny.Sequence
	Ty   Ty
}

func (Term_Param) isTerm() {}

func (CompanionStruct_Term_) Create_Param_(Path _dafny.Sequence, Ty Ty) Term {
	return Term{Term_Param{Path, Ty}}
}

func (_this Term) Is_Param() bool {
	_, ok := _this.Get_().(Term_Param)
	return ok
}

type Term_Lit struct {
	V V
}

func (Term_Lit) isTerm() {}

func (CompanionStruct_Term_) Create_Lit_(V V) Term {
	return Term{Term_Lit{V}}
}

func (_this Term) Is_Lit() bool {
	_, ok := _this.Get_().(Term_Lit)
	return ok
}

type Term_HistAgg struct {
	Bid _dafny.Sequence
	U   Unit
}

func (Term_HistAgg) isTerm() {}

func (CompanionStruct_Term_) Create_HistAgg_(Bid _dafny.Sequence, U Unit) Term {
	return Term{Term_HistAgg{Bid, U}}
}

func (_this Term) Is_HistAgg() bool {
	_, ok := _this.Get_().(Term_HistAgg)
	return ok
}

func (CompanionStruct_Term_) Default() Term {
	return Companion_Term_.Create_Param_(_dafny.EmptySeq, Companion_Ty_.Default())
}

func (_this Term) Dtor_path() _dafny.Sequence {
	return _this.Get_().(Term_Param).Path
}

func (_this Term) Dtor_ty() Ty {
	return _this.Get_().(Term_Param).Ty
}

func (_this Term) Dtor_v() V {
	return _this.Get_().(Term_Lit).V
}

func (_this Term) Dtor_bid() _dafny.Sequence {
	return _this.Get_().(Term_HistAgg).Bid
}

func (_this Term) Dtor_u() Unit {
	return _this.Get_().(Term_HistAgg).U
}

func (_this Term) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Term_Param:
		{
			return "GoalIr.Term.Param" + "(" + data.Path.VerbatimString(true) + ", " + _dafny.String(data.Ty) + ")"
		}
	case Term_Lit:
		{
			return "GoalIr.Term.Lit" + "(" + _dafny.String(data.V) + ")"
		}
	case Term_HistAgg:
		{
			return "GoalIr.Term.HistAgg" + "(" + data.Bid.VerbatimString(true) + ", " + _dafny.String(data.U) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Term) Equals(other Term) bool {
	switch data1 := _this.Get_().(type) {
	case Term_Param:
		{
			data2, ok := other.Get_().(Term_Param)
			return ok && data1.Path.Equals(data2.Path) && data1.Ty.Equals(data2.Ty)
		}
	case Term_Lit:
		{
			data2, ok := other.Get_().(Term_Lit)
			return ok && data1.V.Equals(data2.V)
		}
	case Term_HistAgg:
		{
			data2, ok := other.Get_().(Term_HistAgg)
			return ok && data1.Bid.Equals(data2.Bid) && data1.U.Equals(data2.U)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Term) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Term)
	return ok && _this.Equals(typed)
}

func Type_Term_() _dafny.TypeDescriptor {
	return type_Term_{}
}

type type_Term_ struct {
}

func (_this type_Term_) Default() interface{} {
	return Companion_Term_.Default()
}

func (_this type_Term_) String() string {
	return "GoalIr.Term"
}
func (_this Term) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Term{}

// End of datatype Term

// Definition of datatype Op
type Op struct {
	Data_Op_
}

func (_this Op) Get_() Data_Op_ {
	return _this.Data_Op_
}

type Data_Op_ interface {
	isOp()
}

type CompanionStruct_Op_ struct {
}

var Companion_Op_ = CompanionStruct_Op_{}

type Op_Eq struct {
}

func (Op_Eq) isOp() {}

func (CompanionStruct_Op_) Create_Eq_() Op {
	return Op{Op_Eq{}}
}

func (_this Op) Is_Eq() bool {
	_, ok := _this.Get_().(Op_Eq)
	return ok
}

type Op_Ne struct {
}

func (Op_Ne) isOp() {}

func (CompanionStruct_Op_) Create_Ne_() Op {
	return Op{Op_Ne{}}
}

func (_this Op) Is_Ne() bool {
	_, ok := _this.Get_().(Op_Ne)
	return ok
}

type Op_Lt struct {
}

func (Op_Lt) isOp() {}

func (CompanionStruct_Op_) Create_Lt_() Op {
	return Op{Op_Lt{}}
}

func (_this Op) Is_Lt() bool {
	_, ok := _this.Get_().(Op_Lt)
	return ok
}

type Op_Lte struct {
}

func (Op_Lte) isOp() {}

func (CompanionStruct_Op_) Create_Lte_() Op {
	return Op{Op_Lte{}}
}

func (_this Op) Is_Lte() bool {
	_, ok := _this.Get_().(Op_Lte)
	return ok
}

type Op_Gt struct {
}

func (Op_Gt) isOp() {}

func (CompanionStruct_Op_) Create_Gt_() Op {
	return Op{Op_Gt{}}
}

func (_this Op) Is_Gt() bool {
	_, ok := _this.Get_().(Op_Gt)
	return ok
}

type Op_Gte struct {
}

func (Op_Gte) isOp() {}

func (CompanionStruct_Op_) Create_Gte_() Op {
	return Op{Op_Gte{}}
}

func (_this Op) Is_Gte() bool {
	_, ok := _this.Get_().(Op_Gte)
	return ok
}

type Op_In struct {
}

func (Op_In) isOp() {}

func (CompanionStruct_Op_) Create_In_() Op {
	return Op{Op_In{}}
}

func (_this Op) Is_In() bool {
	_, ok := _this.Get_().(Op_In)
	return ok
}

type Op_Nin struct {
}

func (Op_Nin) isOp() {}

func (CompanionStruct_Op_) Create_Nin_() Op {
	return Op{Op_Nin{}}
}

func (_this Op) Is_Nin() bool {
	_, ok := _this.Get_().(Op_Nin)
	return ok
}

func (CompanionStruct_Op_) Default() Op {
	return Companion_Op_.Create_Eq_()
}

func (_ CompanionStruct_Op_) AllSingletonConstructors() _dafny.Iterator {
	i := -1
	return func() (interface{}, bool) {
		i++
		switch i {
		case 0:
			return Companion_Op_.Create_Eq_(), true
		case 1:
			return Companion_Op_.Create_Ne_(), true
		case 2:
			return Companion_Op_.Create_Lt_(), true
		case 3:
			return Companion_Op_.Create_Lte_(), true
		case 4:
			return Companion_Op_.Create_Gt_(), true
		case 5:
			return Companion_Op_.Create_Gte_(), true
		case 6:
			return Companion_Op_.Create_In_(), true
		case 7:
			return Companion_Op_.Create_Nin_(), true
		default:
			return Op{}, false
		}
	}
}

func (_this Op) String() string {
	switch _this.Get_().(type) {
	case nil:
		return "null"
	case Op_Eq:
		{
			return "GoalIr.Op.Eq"
		}
	case Op_Ne:
		{
			return "GoalIr.Op.Ne"
		}
	case Op_Lt:
		{
			return "GoalIr.Op.Lt"
		}
	case Op_Lte:
		{
			return "GoalIr.Op.Lte"
		}
	case Op_Gt:
		{
			return "GoalIr.Op.Gt"
		}
	case Op_Gte:
		{
			return "GoalIr.Op.Gte"
		}
	case Op_In:
		{
			return "GoalIr.Op.In"
		}
	case Op_Nin:
		{
			return "GoalIr.Op.Nin"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Op) Equals(other Op) bool {
	switch _this.Get_().(type) {
	case Op_Eq:
		{
			_, ok := other.Get_().(Op_Eq)
			return ok
		}
	case Op_Ne:
		{
			_, ok := other.Get_().(Op_Ne)
			return ok
		}
	case Op_Lt:
		{
			_, ok := other.Get_().(Op_Lt)
			return ok
		}
	case Op_Lte:
		{
			_, ok := other.Get_().(Op_Lte)
			return ok
		}
	case Op_Gt:
		{
			_, ok := other.Get_().(Op_Gt)
			return ok
		}
	case Op_Gte:
		{
			_, ok := other.Get_().(Op_Gte)
			return ok
		}
	case Op_In:
		{
			_, ok := other.Get_().(Op_In)
			return ok
		}
	case Op_Nin:
		{
			_, ok := other.Get_().(Op_Nin)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Op) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Op)
	return ok && _this.Equals(typed)
}

func Type_Op_() _dafny.TypeDescriptor {
	return type_Op_{}
}

type type_Op_ struct {
}

func (_this type_Op_) Default() interface{} {
	return Companion_Op_.Default()
}

func (_this type_Op_) String() string {
	return "GoalIr.Op"
}
func (_this Op) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Op{}

// End of datatype Op

// Definition of datatype Cond
type Cond struct {
	Data_Cond_
}

func (_this Cond) Get_() Data_Cond_ {
	return _this.Data_Cond_
}

type Data_Cond_ interface {
	isCond()
}

type CompanionStruct_Cond_ struct {
}

var Companion_Cond_ = CompanionStruct_Cond_{}

type Cond_CTrue struct {
}

func (Cond_CTrue) isCond() {}

func (CompanionStruct_Cond_) Create_CTrue_() Cond {
	return Cond{Cond_CTrue{}}
}

func (_this Cond) Is_CTrue() bool {
	_, ok := _this.Get_().(Cond_CTrue)
	return ok
}

type Cond_Cmp struct {
	Op Op
	L  Term
	R  Term
}

func (Cond_Cmp) isCond() {}

func (CompanionStruct_Cond_) Create_Cmp_(Op Op, L Term, R Term) Cond {
	return Cond{Cond_Cmp{Op, L, R}}
}

func (_this Cond) Is_Cmp() bool {
	_, ok := _this.Get_().(Cond_Cmp)
	return ok
}

type Cond_And struct {
	A Cond
	B Cond
}

func (Cond_And) isCond() {}

func (CompanionStruct_Cond_) Create_And_(A Cond, B Cond) Cond {
	return Cond{Cond_And{A, B}}
}

func (_this Cond) Is_And() bool {
	_, ok := _this.Get_().(Cond_And)
	return ok
}

type Cond_Or struct {
	A Cond
	B Cond
}

func (Cond_Or) isCond() {}

func (CompanionStruct_Cond_) Create_Or_(A Cond, B Cond) Cond {
	return Cond{Cond_Or{A, B}}
}

func (_this Cond) Is_Or() bool {
	_, ok := _this.Get_().(Cond_Or)
	return ok
}

type Cond_Not struct {
	C Cond
}

func (Cond_Not) isCond() {}

func (CompanionStruct_Cond_) Create_Not_(C Cond) Cond {
	return Cond{Cond_Not{C}}
}

func (_this Cond) Is_Not() bool {
	_, ok := _this.Get_().(Cond_Not)
	return ok
}

func (CompanionStruct_Cond_) Default() Cond {
	return Companion_Cond_.Create_CTrue_()
}

func (_this Cond) Dtor_op() Op {
	return _this.Get_().(Cond_Cmp).Op
}

func (_this Cond) Dtor_l() Term {
	return _this.Get_().(Cond_Cmp).L
}

func (_this Cond) Dtor_r() Term {
	return _this.Get_().(Cond_Cmp).R
}

func (_this Cond) Dtor_a() Cond {
	switch data := _this.Get_().(type) {
	case Cond_And:
		return data.A
	default:
		return data.(Cond_Or).A
	}
}

func (_this Cond) Dtor_b() Cond {
	switch data := _this.Get_().(type) {
	case Cond_And:
		return data.B
	default:
		return data.(Cond_Or).B
	}
}

func (_this Cond) Dtor_c() Cond {
	return _this.Get_().(Cond_Not).C
}

func (_this Cond) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Cond_CTrue:
		{
			return "GoalIr.Cond.CTrue"
		}
	case Cond_Cmp:
		{
			return "GoalIr.Cond.Cmp" + "(" + _dafny.String(data.Op) + ", " + _dafny.String(data.L) + ", " + _dafny.String(data.R) + ")"
		}
	case Cond_And:
		{
			return "GoalIr.Cond.And" + "(" + _dafny.String(data.A) + ", " + _dafny.String(data.B) + ")"
		}
	case Cond_Or:
		{
			return "GoalIr.Cond.Or" + "(" + _dafny.String(data.A) + ", " + _dafny.String(data.B) + ")"
		}
	case Cond_Not:
		{
			return "GoalIr.Cond.Not" + "(" + _dafny.String(data.C) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Cond) Equals(other Cond) bool {
	switch data1 := _this.Get_().(type) {
	case Cond_CTrue:
		{
			_, ok := other.Get_().(Cond_CTrue)
			return ok
		}
	case Cond_Cmp:
		{
			data2, ok := other.Get_().(Cond_Cmp)
			return ok && data1.Op.Equals(data2.Op) && data1.L.Equals(data2.L) && data1.R.Equals(data2.R)
		}
	case Cond_And:
		{
			data2, ok := other.Get_().(Cond_And)
			return ok && data1.A.Equals(data2.A) && data1.B.Equals(data2.B)
		}
	case Cond_Or:
		{
			data2, ok := other.Get_().(Cond_Or)
			return ok && data1.A.Equals(data2.A) && data1.B.Equals(data2.B)
		}
	case Cond_Not:
		{
			data2, ok := other.Get_().(Cond_Not)
			return ok && data1.C.Equals(data2.C)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Cond) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Cond)
	return ok && _this.Equals(typed)
}

func Type_Cond_() _dafny.TypeDescriptor {
	return type_Cond_{}
}

type type_Cond_ struct {
}

func (_this type_Cond_) Default() interface{} {
	return Companion_Cond_.Default()
}

func (_this type_Cond_) String() string {
	return "GoalIr.Cond"
}
func (_this Cond) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Cond{}

// End of datatype Cond

// Definition of datatype ResPart
type ResPart struct {
	Data_ResPart_
}

func (_this ResPart) Get_() Data_ResPart_ {
	return _this.Data_ResPart_
}

type Data_ResPart_ interface {
	isResPart()
}

type CompanionStruct_ResPart_ struct {
}

var Companion_ResPart_ = CompanionStruct_ResPart_{}

type ResPart_PartExact struct {
	Id _dafny.Sequence
}

func (ResPart_PartExact) isResPart() {}

func (CompanionStruct_ResPart_) Create_PartExact_(Id _dafny.Sequence) ResPart {
	return ResPart{ResPart_PartExact{Id}}
}

func (_this ResPart) Is_PartExact() bool {
	_, ok := _this.Get_().(ResPart_PartExact)
	return ok
}

type ResPart_PartOneOf struct {
	Ids _dafny.Sequence
}

func (ResPart_PartOneOf) isResPart() {}

func (CompanionStruct_ResPart_) Create_PartOneOf_(Ids _dafny.Sequence) ResPart {
	return ResPart{ResPart_PartOneOf{Ids}}
}

func (_this ResPart) Is_PartOneOf() bool {
	_, ok := _this.Get_().(ResPart_PartOneOf)
	return ok
}

type ResPart_PartRelated struct {
	Rel    _dafny.Sequence
	Anchor _dafny.Sequence
}

func (ResPart_PartRelated) isResPart() {}

func (CompanionStruct_ResPart_) Create_PartRelated_(Rel _dafny.Sequence, Anchor _dafny.Sequence) ResPart {
	return ResPart{ResPart_PartRelated{Rel, Anchor}}
}

func (_this ResPart) Is_PartRelated() bool {
	_, ok := _this.Get_().(ResPart_PartRelated)
	return ok
}

func (CompanionStruct_ResPart_) Default() ResPart {
	return Companion_ResPart_.Create_PartExact_(_dafny.EmptySeq)
}

func (_this ResPart) Dtor_id() _dafny.Sequence {
	return _this.Get_().(ResPart_PartExact).Id
}

func (_this ResPart) Dtor_ids() _dafny.Sequence {
	return _this.Get_().(ResPart_PartOneOf).Ids
}

func (_this ResPart) Dtor_rel() _dafny.Sequence {
	return _this.Get_().(ResPart_PartRelated).Rel
}

func (_this ResPart) Dtor_anchor() _dafny.Sequence {
	return _this.Get_().(ResPart_PartRelated).Anchor
}

func (_this ResPart) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case ResPart_PartExact:
		{
			return "GoalIr.ResPart.PartExact" + "(" + data.Id.VerbatimString(true) + ")"
		}
	case ResPart_PartOneOf:
		{
			return "GoalIr.ResPart.PartOneOf" + "(" + _dafny.String(data.Ids) + ")"
		}
	case ResPart_PartRelated:
		{
			return "GoalIr.ResPart.PartRelated" + "(" + data.Rel.VerbatimString(true) + ", " + data.Anchor.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this ResPart) Equals(other ResPart) bool {
	switch data1 := _this.Get_().(type) {
	case ResPart_PartExact:
		{
			data2, ok := other.Get_().(ResPart_PartExact)
			return ok && data1.Id.Equals(data2.Id)
		}
	case ResPart_PartOneOf:
		{
			data2, ok := other.Get_().(ResPart_PartOneOf)
			return ok && data1.Ids.Equals(data2.Ids)
		}
	case ResPart_PartRelated:
		{
			data2, ok := other.Get_().(ResPart_PartRelated)
			return ok && data1.Rel.Equals(data2.Rel) && data1.Anchor.Equals(data2.Anchor)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this ResPart) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(ResPart)
	return ok && _this.Equals(typed)
}

func Type_ResPart_() _dafny.TypeDescriptor {
	return type_ResPart_{}
}

type type_ResPart_ struct {
}

func (_this type_ResPart_) Default() interface{} {
	return Companion_ResPart_.Default()
}

func (_this type_ResPart_) String() string {
	return "GoalIr.ResPart"
}
func (_this ResPart) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = ResPart{}

// End of datatype ResPart

// Definition of datatype ResSel
type ResSel struct {
	Data_ResSel_
}

func (_this ResSel) Get_() Data_ResSel_ {
	return _this.Data_ResSel_
}

type Data_ResSel_ interface {
	isResSel()
}

type CompanionStruct_ResSel_ struct {
}

var Companion_ResSel_ = CompanionStruct_ResSel_{}

type ResSel_Exact struct {
	Id _dafny.Sequence
}

func (ResSel_Exact) isResSel() {}

func (CompanionStruct_ResSel_) Create_Exact_(Id _dafny.Sequence) ResSel {
	return ResSel{ResSel_Exact{Id}}
}

func (_this ResSel) Is_Exact() bool {
	_, ok := _this.Get_().(ResSel_Exact)
	return ok
}

type ResSel_OneOf struct {
	Ids _dafny.Sequence
}

func (ResSel_OneOf) isResSel() {}

func (CompanionStruct_ResSel_) Create_OneOf_(Ids _dafny.Sequence) ResSel {
	return ResSel{ResSel_OneOf{Ids}}
}

func (_this ResSel) Is_OneOf() bool {
	_, ok := _this.Get_().(ResSel_OneOf)
	return ok
}

type ResSel_Related struct {
	Rel    _dafny.Sequence
	Anchor _dafny.Sequence
}

func (ResSel_Related) isResSel() {}

func (CompanionStruct_ResSel_) Create_Related_(Rel _dafny.Sequence, Anchor _dafny.Sequence) ResSel {
	return ResSel{ResSel_Related{Rel, Anchor}}
}

func (_this ResSel) Is_Related() bool {
	_, ok := _this.Get_().(ResSel_Related)
	return ok
}

type ResSel_AnyRes struct {
	Reason _dafny.Sequence
}

func (ResSel_AnyRes) isResSel() {}

func (CompanionStruct_ResSel_) Create_AnyRes_(Reason _dafny.Sequence) ResSel {
	return ResSel{ResSel_AnyRes{Reason}}
}

func (_this ResSel) Is_AnyRes() bool {
	_, ok := _this.Get_().(ResSel_AnyRes)
	return ok
}

type ResSel_AllOf struct {
	Parts _dafny.Sequence
}

func (ResSel_AllOf) isResSel() {}

func (CompanionStruct_ResSel_) Create_AllOf_(Parts _dafny.Sequence) ResSel {
	return ResSel{ResSel_AllOf{Parts}}
}

func (_this ResSel) Is_AllOf() bool {
	_, ok := _this.Get_().(ResSel_AllOf)
	return ok
}

func (CompanionStruct_ResSel_) Default() ResSel {
	return Companion_ResSel_.Create_Exact_(_dafny.EmptySeq)
}

func (_this ResSel) Dtor_id() _dafny.Sequence {
	return _this.Get_().(ResSel_Exact).Id
}

func (_this ResSel) Dtor_ids() _dafny.Sequence {
	return _this.Get_().(ResSel_OneOf).Ids
}

func (_this ResSel) Dtor_rel() _dafny.Sequence {
	return _this.Get_().(ResSel_Related).Rel
}

func (_this ResSel) Dtor_anchor() _dafny.Sequence {
	return _this.Get_().(ResSel_Related).Anchor
}

func (_this ResSel) Dtor_reason() _dafny.Sequence {
	return _this.Get_().(ResSel_AnyRes).Reason
}

func (_this ResSel) Dtor_parts() _dafny.Sequence {
	return _this.Get_().(ResSel_AllOf).Parts
}

func (_this ResSel) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case ResSel_Exact:
		{
			return "GoalIr.ResSel.Exact" + "(" + data.Id.VerbatimString(true) + ")"
		}
	case ResSel_OneOf:
		{
			return "GoalIr.ResSel.OneOf" + "(" + _dafny.String(data.Ids) + ")"
		}
	case ResSel_Related:
		{
			return "GoalIr.ResSel.Related" + "(" + data.Rel.VerbatimString(true) + ", " + data.Anchor.VerbatimString(true) + ")"
		}
	case ResSel_AnyRes:
		{
			return "GoalIr.ResSel.AnyRes" + "(" + data.Reason.VerbatimString(true) + ")"
		}
	case ResSel_AllOf:
		{
			return "GoalIr.ResSel.AllOf" + "(" + _dafny.String(data.Parts) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this ResSel) Equals(other ResSel) bool {
	switch data1 := _this.Get_().(type) {
	case ResSel_Exact:
		{
			data2, ok := other.Get_().(ResSel_Exact)
			return ok && data1.Id.Equals(data2.Id)
		}
	case ResSel_OneOf:
		{
			data2, ok := other.Get_().(ResSel_OneOf)
			return ok && data1.Ids.Equals(data2.Ids)
		}
	case ResSel_Related:
		{
			data2, ok := other.Get_().(ResSel_Related)
			return ok && data1.Rel.Equals(data2.Rel) && data1.Anchor.Equals(data2.Anchor)
		}
	case ResSel_AnyRes:
		{
			data2, ok := other.Get_().(ResSel_AnyRes)
			return ok && data1.Reason.Equals(data2.Reason)
		}
	case ResSel_AllOf:
		{
			data2, ok := other.Get_().(ResSel_AllOf)
			return ok && data1.Parts.Equals(data2.Parts)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this ResSel) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(ResSel)
	return ok && _this.Equals(typed)
}

func Type_ResSel_() _dafny.TypeDescriptor {
	return type_ResSel_{}
}

type type_ResSel_ struct {
}

func (_this type_ResSel_) Default() interface{} {
	return Companion_ResSel_.Default()
}

func (_this type_ResSel_) String() string {
	return "GoalIr.ResSel"
}
func (_this ResSel) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = ResSel{}

// End of datatype ResSel

// Definition of datatype Grant
type Grant struct {
	Data_Grant_
}

func (_this Grant) Get_() Data_Grant_ {
	return _this.Data_Grant_
}

type Data_Grant_ interface {
	isGrant()
}

type CompanionStruct_Grant_ struct {
}

var Companion_Grant_ = CompanionStruct_Grant_{}

type Grant_Grant struct {
	Gid  _dafny.Sequence
	Verb _dafny.Sequence
	Res  ResSel
	Cond Cond
}

func (Grant_Grant) isGrant() {}

func (CompanionStruct_Grant_) Create_Grant_(Gid _dafny.Sequence, Verb _dafny.Sequence, Res ResSel, Cond Cond) Grant {
	return Grant{Grant_Grant{Gid, Verb, Res, Cond}}
}

func (_this Grant) Is_Grant() bool {
	_, ok := _this.Get_().(Grant_Grant)
	return ok
}

func (CompanionStruct_Grant_) Default() Grant {
	return Companion_Grant_.Create_Grant_(_dafny.EmptySeq, _dafny.EmptySeq, Companion_ResSel_.Default(), Companion_Cond_.Default())
}

func (_this Grant) Dtor_gid() _dafny.Sequence {
	return _this.Get_().(Grant_Grant).Gid
}

func (_this Grant) Dtor_verb() _dafny.Sequence {
	return _this.Get_().(Grant_Grant).Verb
}

func (_this Grant) Dtor_res() ResSel {
	return _this.Get_().(Grant_Grant).Res
}

func (_this Grant) Dtor_cond() Cond {
	return _this.Get_().(Grant_Grant).Cond
}

func (_this Grant) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Grant_Grant:
		{
			return "GoalIr.Grant.Grant" + "(" + data.Gid.VerbatimString(true) + ", " + data.Verb.VerbatimString(true) + ", " + _dafny.String(data.Res) + ", " + _dafny.String(data.Cond) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Grant) Equals(other Grant) bool {
	switch data1 := _this.Get_().(type) {
	case Grant_Grant:
		{
			data2, ok := other.Get_().(Grant_Grant)
			return ok && data1.Gid.Equals(data2.Gid) && data1.Verb.Equals(data2.Verb) && data1.Res.Equals(data2.Res) && data1.Cond.Equals(data2.Cond)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Grant) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Grant)
	return ok && _this.Equals(typed)
}

func Type_Grant_() _dafny.TypeDescriptor {
	return type_Grant_{}
}

type type_Grant_ struct {
}

func (_this type_Grant_) Default() interface{} {
	return Companion_Grant_.Default()
}

func (_this type_Grant_) String() string {
	return "GoalIr.Grant"
}
func (_this Grant) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Grant{}

// End of datatype Grant

// Definition of datatype ProhTarget
type ProhTarget struct {
	Data_ProhTarget_
}

func (_this ProhTarget) Get_() Data_ProhTarget_ {
	return _this.Data_ProhTarget_
}

type Data_ProhTarget_ interface {
	isProhTarget()
}

type CompanionStruct_ProhTarget_ struct {
}

var Companion_ProhTarget_ = CompanionStruct_ProhTarget_{}

type ProhTarget_PVerb struct {
	Verb _dafny.Sequence
}

func (ProhTarget_PVerb) isProhTarget() {}

func (CompanionStruct_ProhTarget_) Create_PVerb_(Verb _dafny.Sequence) ProhTarget {
	return ProhTarget{ProhTarget_PVerb{Verb}}
}

func (_this ProhTarget) Is_PVerb() bool {
	_, ok := _this.Get_().(ProhTarget_PVerb)
	return ok
}

type ProhTarget_PEffect struct {
	Cls _dafny.Sequence
}

func (ProhTarget_PEffect) isProhTarget() {}

func (CompanionStruct_ProhTarget_) Create_PEffect_(Cls _dafny.Sequence) ProhTarget {
	return ProhTarget{ProhTarget_PEffect{Cls}}
}

func (_this ProhTarget) Is_PEffect() bool {
	_, ok := _this.Get_().(ProhTarget_PEffect)
	return ok
}

func (CompanionStruct_ProhTarget_) Default() ProhTarget {
	return Companion_ProhTarget_.Create_PVerb_(_dafny.EmptySeq)
}

func (_this ProhTarget) Dtor_verb() _dafny.Sequence {
	return _this.Get_().(ProhTarget_PVerb).Verb
}

func (_this ProhTarget) Dtor_cls() _dafny.Sequence {
	return _this.Get_().(ProhTarget_PEffect).Cls
}

func (_this ProhTarget) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case ProhTarget_PVerb:
		{
			return "GoalIr.ProhTarget.PVerb" + "(" + data.Verb.VerbatimString(true) + ")"
		}
	case ProhTarget_PEffect:
		{
			return "GoalIr.ProhTarget.PEffect" + "(" + data.Cls.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this ProhTarget) Equals(other ProhTarget) bool {
	switch data1 := _this.Get_().(type) {
	case ProhTarget_PVerb:
		{
			data2, ok := other.Get_().(ProhTarget_PVerb)
			return ok && data1.Verb.Equals(data2.Verb)
		}
	case ProhTarget_PEffect:
		{
			data2, ok := other.Get_().(ProhTarget_PEffect)
			return ok && data1.Cls.Equals(data2.Cls)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this ProhTarget) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(ProhTarget)
	return ok && _this.Equals(typed)
}

func Type_ProhTarget_() _dafny.TypeDescriptor {
	return type_ProhTarget_{}
}

type type_ProhTarget_ struct {
}

func (_this type_ProhTarget_) Default() interface{} {
	return Companion_ProhTarget_.Default()
}

func (_this type_ProhTarget_) String() string {
	return "GoalIr.ProhTarget"
}
func (_this ProhTarget) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = ProhTarget{}

// End of datatype ProhTarget

// Definition of datatype Prohibit
type Prohibit struct {
	Data_Prohibit_
}

func (_this Prohibit) Get_() Data_Prohibit_ {
	return _this.Data_Prohibit_
}

type Data_Prohibit_ interface {
	isProhibit()
}

type CompanionStruct_Prohibit_ struct {
}

var Companion_Prohibit_ = CompanionStruct_Prohibit_{}

type Prohibit_Prohibit struct {
	Pid    _dafny.Sequence
	Target ProhTarget
	Res    ResSel
	Cond   Cond
}

func (Prohibit_Prohibit) isProhibit() {}

func (CompanionStruct_Prohibit_) Create_Prohibit_(Pid _dafny.Sequence, Target ProhTarget, Res ResSel, Cond Cond) Prohibit {
	return Prohibit{Prohibit_Prohibit{Pid, Target, Res, Cond}}
}

func (_this Prohibit) Is_Prohibit() bool {
	_, ok := _this.Get_().(Prohibit_Prohibit)
	return ok
}

func (CompanionStruct_Prohibit_) Default() Prohibit {
	return Companion_Prohibit_.Create_Prohibit_(_dafny.EmptySeq, Companion_ProhTarget_.Default(), Companion_ResSel_.Default(), Companion_Cond_.Default())
}

func (_this Prohibit) Dtor_pid() _dafny.Sequence {
	return _this.Get_().(Prohibit_Prohibit).Pid
}

func (_this Prohibit) Dtor_target() ProhTarget {
	return _this.Get_().(Prohibit_Prohibit).Target
}

func (_this Prohibit) Dtor_res() ResSel {
	return _this.Get_().(Prohibit_Prohibit).Res
}

func (_this Prohibit) Dtor_cond() Cond {
	return _this.Get_().(Prohibit_Prohibit).Cond
}

func (_this Prohibit) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Prohibit_Prohibit:
		{
			return "GoalIr.Prohibit.Prohibit" + "(" + data.Pid.VerbatimString(true) + ", " + _dafny.String(data.Target) + ", " + _dafny.String(data.Res) + ", " + _dafny.String(data.Cond) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Prohibit) Equals(other Prohibit) bool {
	switch data1 := _this.Get_().(type) {
	case Prohibit_Prohibit:
		{
			data2, ok := other.Get_().(Prohibit_Prohibit)
			return ok && data1.Pid.Equals(data2.Pid) && data1.Target.Equals(data2.Target) && data1.Res.Equals(data2.Res) && data1.Cond.Equals(data2.Cond)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Prohibit) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Prohibit)
	return ok && _this.Equals(typed)
}

func Type_Prohibit_() _dafny.TypeDescriptor {
	return type_Prohibit_{}
}

type type_Prohibit_ struct {
}

func (_this type_Prohibit_) Default() interface{} {
	return Companion_Prohibit_.Default()
}

func (_this type_Prohibit_) String() string {
	return "GoalIr.Prohibit"
}
func (_this Prohibit) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Prohibit{}

// End of datatype Prohibit

// Definition of datatype Agg
type Agg struct {
	Data_Agg_
}

func (_this Agg) Get_() Data_Agg_ {
	return _this.Data_Agg_
}

type Data_Agg_ interface {
	isAgg()
}

type CompanionStruct_Agg_ struct {
}

var Companion_Agg_ = CompanionStruct_Agg_{}

type Agg_ACount struct {
}

func (Agg_ACount) isAgg() {}

func (CompanionStruct_Agg_) Create_ACount_() Agg {
	return Agg{Agg_ACount{}}
}

func (_this Agg) Is_ACount() bool {
	_, ok := _this.Get_().(Agg_ACount)
	return ok
}

type Agg_ASum struct {
}

func (Agg_ASum) isAgg() {}

func (CompanionStruct_Agg_) Create_ASum_() Agg {
	return Agg{Agg_ASum{}}
}

func (_this Agg) Is_ASum() bool {
	_, ok := _this.Get_().(Agg_ASum)
	return ok
}

type Agg_AMax struct {
}

func (Agg_AMax) isAgg() {}

func (CompanionStruct_Agg_) Create_AMax_() Agg {
	return Agg{Agg_AMax{}}
}

func (_this Agg) Is_AMax() bool {
	_, ok := _this.Get_().(Agg_AMax)
	return ok
}

type Agg_ADistinct struct {
}

func (Agg_ADistinct) isAgg() {}

func (CompanionStruct_Agg_) Create_ADistinct_() Agg {
	return Agg{Agg_ADistinct{}}
}

func (_this Agg) Is_ADistinct() bool {
	_, ok := _this.Get_().(Agg_ADistinct)
	return ok
}

func (CompanionStruct_Agg_) Default() Agg {
	return Companion_Agg_.Create_ACount_()
}

func (_ CompanionStruct_Agg_) AllSingletonConstructors() _dafny.Iterator {
	i := -1
	return func() (interface{}, bool) {
		i++
		switch i {
		case 0:
			return Companion_Agg_.Create_ACount_(), true
		case 1:
			return Companion_Agg_.Create_ASum_(), true
		case 2:
			return Companion_Agg_.Create_AMax_(), true
		case 3:
			return Companion_Agg_.Create_ADistinct_(), true
		default:
			return Agg{}, false
		}
	}
}

func (_this Agg) String() string {
	switch _this.Get_().(type) {
	case nil:
		return "null"
	case Agg_ACount:
		{
			return "GoalIr.Agg.ACount"
		}
	case Agg_ASum:
		{
			return "GoalIr.Agg.ASum"
		}
	case Agg_AMax:
		{
			return "GoalIr.Agg.AMax"
		}
	case Agg_ADistinct:
		{
			return "GoalIr.Agg.ADistinct"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Agg) Equals(other Agg) bool {
	switch _this.Get_().(type) {
	case Agg_ACount:
		{
			_, ok := other.Get_().(Agg_ACount)
			return ok
		}
	case Agg_ASum:
		{
			_, ok := other.Get_().(Agg_ASum)
			return ok
		}
	case Agg_AMax:
		{
			_, ok := other.Get_().(Agg_AMax)
			return ok
		}
	case Agg_ADistinct:
		{
			_, ok := other.Get_().(Agg_ADistinct)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Agg) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Agg)
	return ok && _this.Equals(typed)
}

func Type_Agg_() _dafny.TypeDescriptor {
	return type_Agg_{}
}

type type_Agg_ struct {
}

func (_this type_Agg_) Default() interface{} {
	return Companion_Agg_.Default()
}

func (_this type_Agg_) String() string {
	return "GoalIr.Agg"
}
func (_this Agg) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Agg{}

// End of datatype Agg

// Definition of datatype Sel
type Sel struct {
	Data_Sel_
}

func (_this Sel) Get_() Data_Sel_ {
	return _this.Data_Sel_
}

type Data_Sel_ interface {
	isSel()
}

type CompanionStruct_Sel_ struct {
}

var Companion_Sel_ = CompanionStruct_Sel_{}

type Sel_SelGids struct {
	Gids _dafny.Sequence
}

func (Sel_SelGids) isSel() {}

func (CompanionStruct_Sel_) Create_SelGids_(Gids _dafny.Sequence) Sel {
	return Sel{Sel_SelGids{Gids}}
}

func (_this Sel) Is_SelGids() bool {
	_, ok := _this.Get_().(Sel_SelGids)
	return ok
}

type Sel_SelEffect struct {
	Cls _dafny.Sequence
}

func (Sel_SelEffect) isSel() {}

func (CompanionStruct_Sel_) Create_SelEffect_(Cls _dafny.Sequence) Sel {
	return Sel{Sel_SelEffect{Cls}}
}

func (_this Sel) Is_SelEffect() bool {
	_, ok := _this.Get_().(Sel_SelEffect)
	return ok
}

func (CompanionStruct_Sel_) Default() Sel {
	return Companion_Sel_.Create_SelGids_(_dafny.EmptySeq)
}

func (_this Sel) Dtor_gids() _dafny.Sequence {
	return _this.Get_().(Sel_SelGids).Gids
}

func (_this Sel) Dtor_cls() _dafny.Sequence {
	return _this.Get_().(Sel_SelEffect).Cls
}

func (_this Sel) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Sel_SelGids:
		{
			return "GoalIr.Sel.SelGids" + "(" + _dafny.String(data.Gids) + ")"
		}
	case Sel_SelEffect:
		{
			return "GoalIr.Sel.SelEffect" + "(" + data.Cls.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Sel) Equals(other Sel) bool {
	switch data1 := _this.Get_().(type) {
	case Sel_SelGids:
		{
			data2, ok := other.Get_().(Sel_SelGids)
			return ok && data1.Gids.Equals(data2.Gids)
		}
	case Sel_SelEffect:
		{
			data2, ok := other.Get_().(Sel_SelEffect)
			return ok && data1.Cls.Equals(data2.Cls)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Sel) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Sel)
	return ok && _this.Equals(typed)
}

func Type_Sel_() _dafny.TypeDescriptor {
	return type_Sel_{}
}

type type_Sel_ struct {
}

func (_this type_Sel_) Default() interface{} {
	return Companion_Sel_.Default()
}

func (_this type_Sel_) String() string {
	return "GoalIr.Sel"
}
func (_this Sel) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Sel{}

// End of datatype Sel

// Definition of datatype Window
type Window struct {
	Data_Window_
}

func (_this Window) Get_() Data_Window_ {
	return _this.Data_Window_
}

type Data_Window_ interface {
	isWindow()
}

type CompanionStruct_Window_ struct {
}

var Companion_Window_ = CompanionStruct_Window_{}

type Window_WTask struct {
}

func (Window_WTask) isWindow() {}

func (CompanionStruct_Window_) Create_WTask_() Window {
	return Window{Window_WTask{}}
}

func (_this Window) Is_WTask() bool {
	_, ok := _this.Get_().(Window_WTask)
	return ok
}

type Window_WSliding struct {
	Ms _dafny.Int
}

func (Window_WSliding) isWindow() {}

func (CompanionStruct_Window_) Create_WSliding_(Ms _dafny.Int) Window {
	return Window{Window_WSliding{Ms}}
}

func (_this Window) Is_WSliding() bool {
	_, ok := _this.Get_().(Window_WSliding)
	return ok
}

type Window_WPeriod struct {
	Ms _dafny.Int
	T0 _dafny.Int
}

func (Window_WPeriod) isWindow() {}

func (CompanionStruct_Window_) Create_WPeriod_(Ms _dafny.Int, T0 _dafny.Int) Window {
	return Window{Window_WPeriod{Ms, T0}}
}

func (_this Window) Is_WPeriod() bool {
	_, ok := _this.Get_().(Window_WPeriod)
	return ok
}

type Window_WLifetime struct {
}

func (Window_WLifetime) isWindow() {}

func (CompanionStruct_Window_) Create_WLifetime_() Window {
	return Window{Window_WLifetime{}}
}

func (_this Window) Is_WLifetime() bool {
	_, ok := _this.Get_().(Window_WLifetime)
	return ok
}

func (CompanionStruct_Window_) Default() Window {
	return Companion_Window_.Create_WTask_()
}

func (_this Window) Dtor_ms() _dafny.Int {
	switch data := _this.Get_().(type) {
	case Window_WSliding:
		return data.Ms
	default:
		return data.(Window_WPeriod).Ms
	}
}

func (_this Window) Dtor_t0() _dafny.Int {
	return _this.Get_().(Window_WPeriod).T0
}

func (_this Window) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Window_WTask:
		{
			return "GoalIr.Window.WTask"
		}
	case Window_WSliding:
		{
			return "GoalIr.Window.WSliding" + "(" + _dafny.String(data.Ms) + ")"
		}
	case Window_WPeriod:
		{
			return "GoalIr.Window.WPeriod" + "(" + _dafny.String(data.Ms) + ", " + _dafny.String(data.T0) + ")"
		}
	case Window_WLifetime:
		{
			return "GoalIr.Window.WLifetime"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Window) Equals(other Window) bool {
	switch data1 := _this.Get_().(type) {
	case Window_WTask:
		{
			_, ok := other.Get_().(Window_WTask)
			return ok
		}
	case Window_WSliding:
		{
			data2, ok := other.Get_().(Window_WSliding)
			return ok && data1.Ms.Cmp(data2.Ms) == 0
		}
	case Window_WPeriod:
		{
			data2, ok := other.Get_().(Window_WPeriod)
			return ok && data1.Ms.Cmp(data2.Ms) == 0 && data1.T0.Cmp(data2.T0) == 0
		}
	case Window_WLifetime:
		{
			_, ok := other.Get_().(Window_WLifetime)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Window) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Window)
	return ok && _this.Equals(typed)
}

func Type_Window_() _dafny.TypeDescriptor {
	return type_Window_{}
}

type type_Window_ struct {
}

func (_this type_Window_) Default() interface{} {
	return Companion_Window_.Default()
}

func (_this type_Window_) String() string {
	return "GoalIr.Window"
}
func (_this Window) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Window{}

// End of datatype Window

// Definition of datatype Scope
type Scope struct {
	Data_Scope_
}

func (_this Scope) Get_() Data_Scope_ {
	return _this.Data_Scope_
}

type Data_Scope_ interface {
	isScope()
}

type CompanionStruct_Scope_ struct {
}

var Companion_Scope_ = CompanionStruct_Scope_{}

type Scope_SSession struct {
}

func (Scope_SSession) isScope() {}

func (CompanionStruct_Scope_) Create_SSession_() Scope {
	return Scope{Scope_SSession{}}
}

func (_this Scope) Is_SSession() bool {
	_, ok := _this.Get_().(Scope_SSession)
	return ok
}

type Scope_SPrincipal struct {
}

func (Scope_SPrincipal) isScope() {}

func (CompanionStruct_Scope_) Create_SPrincipal_() Scope {
	return Scope{Scope_SPrincipal{}}
}

func (_this Scope) Is_SPrincipal() bool {
	_, ok := _this.Get_().(Scope_SPrincipal)
	return ok
}

type Scope_SOrg struct {
}

func (Scope_SOrg) isScope() {}

func (CompanionStruct_Scope_) Create_SOrg_() Scope {
	return Scope{Scope_SOrg{}}
}

func (_this Scope) Is_SOrg() bool {
	_, ok := _this.Get_().(Scope_SOrg)
	return ok
}

type Scope_SFleet struct {
	Agents _dafny.Sequence
}

func (Scope_SFleet) isScope() {}

func (CompanionStruct_Scope_) Create_SFleet_(Agents _dafny.Sequence) Scope {
	return Scope{Scope_SFleet{Agents}}
}

func (_this Scope) Is_SFleet() bool {
	_, ok := _this.Get_().(Scope_SFleet)
	return ok
}

func (CompanionStruct_Scope_) Default() Scope {
	return Companion_Scope_.Create_SSession_()
}

func (_this Scope) Dtor_agents() _dafny.Sequence {
	return _this.Get_().(Scope_SFleet).Agents
}

func (_this Scope) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Scope_SSession:
		{
			return "GoalIr.Scope.SSession"
		}
	case Scope_SPrincipal:
		{
			return "GoalIr.Scope.SPrincipal"
		}
	case Scope_SOrg:
		{
			return "GoalIr.Scope.SOrg"
		}
	case Scope_SFleet:
		{
			return "GoalIr.Scope.SFleet" + "(" + _dafny.String(data.Agents) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Scope) Equals(other Scope) bool {
	switch data1 := _this.Get_().(type) {
	case Scope_SSession:
		{
			_, ok := other.Get_().(Scope_SSession)
			return ok
		}
	case Scope_SPrincipal:
		{
			_, ok := other.Get_().(Scope_SPrincipal)
			return ok
		}
	case Scope_SOrg:
		{
			_, ok := other.Get_().(Scope_SOrg)
			return ok
		}
	case Scope_SFleet:
		{
			data2, ok := other.Get_().(Scope_SFleet)
			return ok && data1.Agents.Equals(data2.Agents)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Scope) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Scope)
	return ok && _this.Equals(typed)
}

func Type_Scope_() _dafny.TypeDescriptor {
	return type_Scope_{}
}

type type_Scope_ struct {
}

func (_this type_Scope_) Default() interface{} {
	return Companion_Scope_.Default()
}

func (_this type_Scope_) String() string {
	return "GoalIr.Scope"
}
func (_this Scope) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Scope{}

// End of datatype Scope

// Definition of datatype OnExceed
type OnExceed struct {
	Data_OnExceed_
}

func (_this OnExceed) Get_() Data_OnExceed_ {
	return _this.Data_OnExceed_
}

type Data_OnExceed_ interface {
	isOnExceed()
}

type CompanionStruct_OnExceed_ struct {
}

var Companion_OnExceed_ = CompanionStruct_OnExceed_{}

type OnExceed_OnDeny struct {
}

func (OnExceed_OnDeny) isOnExceed() {}

func (CompanionStruct_OnExceed_) Create_OnDeny_() OnExceed {
	return OnExceed{OnExceed_OnDeny{}}
}

func (_this OnExceed) Is_OnDeny() bool {
	_, ok := _this.Get_().(OnExceed_OnDeny)
	return ok
}

type OnExceed_OnEscalate struct {
}

func (OnExceed_OnEscalate) isOnExceed() {}

func (CompanionStruct_OnExceed_) Create_OnEscalate_() OnExceed {
	return OnExceed{OnExceed_OnEscalate{}}
}

func (_this OnExceed) Is_OnEscalate() bool {
	_, ok := _this.Get_().(OnExceed_OnEscalate)
	return ok
}

func (CompanionStruct_OnExceed_) Default() OnExceed {
	return Companion_OnExceed_.Create_OnDeny_()
}

func (_ CompanionStruct_OnExceed_) AllSingletonConstructors() _dafny.Iterator {
	i := -1
	return func() (interface{}, bool) {
		i++
		switch i {
		case 0:
			return Companion_OnExceed_.Create_OnDeny_(), true
		case 1:
			return Companion_OnExceed_.Create_OnEscalate_(), true
		default:
			return OnExceed{}, false
		}
	}
}

func (_this OnExceed) String() string {
	switch _this.Get_().(type) {
	case nil:
		return "null"
	case OnExceed_OnDeny:
		{
			return "GoalIr.OnExceed.OnDeny"
		}
	case OnExceed_OnEscalate:
		{
			return "GoalIr.OnExceed.OnEscalate"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this OnExceed) Equals(other OnExceed) bool {
	switch _this.Get_().(type) {
	case OnExceed_OnDeny:
		{
			_, ok := other.Get_().(OnExceed_OnDeny)
			return ok
		}
	case OnExceed_OnEscalate:
		{
			_, ok := other.Get_().(OnExceed_OnEscalate)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this OnExceed) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(OnExceed)
	return ok && _this.Equals(typed)
}

func Type_OnExceed_() _dafny.TypeDescriptor {
	return type_OnExceed_{}
}

type type_OnExceed_ struct {
}

func (_this type_OnExceed_) Default() interface{} {
	return Companion_OnExceed_.Default()
}

func (_this type_OnExceed_) String() string {
	return "GoalIr.OnExceed"
}
func (_this OnExceed) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = OnExceed{}

// End of datatype OnExceed

// Definition of datatype BCore
type BCore struct {
	Data_BCore_
}

func (_this BCore) Get_() Data_BCore_ {
	return _this.Data_BCore_
}

type Data_BCore_ interface {
	isBCore()
}

type CompanionStruct_BCore_ struct {
}

var Companion_BCore_ = CompanionStruct_BCore_{}

type BCore_BCore struct {
	Agg      Agg
	Value    Term
	Key      _dafny.Sequence
	Window   Window
	Scope    Scope
	Cap      Q
	OnExceed OnExceed
}

func (BCore_BCore) isBCore() {}

func (CompanionStruct_BCore_) Create_BCore_(Agg Agg, Value Term, Key _dafny.Sequence, Window Window, Scope Scope, Cap Q, OnExceed OnExceed) BCore {
	return BCore{BCore_BCore{Agg, Value, Key, Window, Scope, Cap, OnExceed}}
}

func (_this BCore) Is_BCore() bool {
	_, ok := _this.Get_().(BCore_BCore)
	return ok
}

func (CompanionStruct_BCore_) Default() BCore {
	return Companion_BCore_.Create_BCore_(Companion_Agg_.Default(), Companion_Term_.Default(), _dafny.EmptySeq, Companion_Window_.Default(), Companion_Scope_.Default(), Companion_Q_.Default(), Companion_OnExceed_.Default())
}

func (_this BCore) Dtor_agg() Agg {
	return _this.Get_().(BCore_BCore).Agg
}

func (_this BCore) Dtor_value() Term {
	return _this.Get_().(BCore_BCore).Value
}

func (_this BCore) Dtor_key() _dafny.Sequence {
	return _this.Get_().(BCore_BCore).Key
}

func (_this BCore) Dtor_window() Window {
	return _this.Get_().(BCore_BCore).Window
}

func (_this BCore) Dtor_scope() Scope {
	return _this.Get_().(BCore_BCore).Scope
}

func (_this BCore) Dtor_cap() Q {
	return _this.Get_().(BCore_BCore).Cap
}

func (_this BCore) Dtor_onExceed() OnExceed {
	return _this.Get_().(BCore_BCore).OnExceed
}

func (_this BCore) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case BCore_BCore:
		{
			return "GoalIr.BCore.BCore" + "(" + _dafny.String(data.Agg) + ", " + _dafny.String(data.Value) + ", " + data.Key.VerbatimString(true) + ", " + _dafny.String(data.Window) + ", " + _dafny.String(data.Scope) + ", " + _dafny.String(data.Cap) + ", " + _dafny.String(data.OnExceed) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this BCore) Equals(other BCore) bool {
	switch data1 := _this.Get_().(type) {
	case BCore_BCore:
		{
			data2, ok := other.Get_().(BCore_BCore)
			return ok && data1.Agg.Equals(data2.Agg) && data1.Value.Equals(data2.Value) && data1.Key.Equals(data2.Key) && data1.Window.Equals(data2.Window) && data1.Scope.Equals(data2.Scope) && data1.Cap.Equals(data2.Cap) && data1.OnExceed.Equals(data2.OnExceed)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this BCore) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(BCore)
	return ok && _this.Equals(typed)
}

func Type_BCore_() _dafny.TypeDescriptor {
	return type_BCore_{}
}

type type_BCore_ struct {
}

func (_this type_BCore_) Default() interface{} {
	return Companion_BCore_.Default()
}

func (_this type_BCore_) String() string {
	return "GoalIr.BCore"
}
func (_this BCore) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = BCore{}

// End of datatype BCore

// Definition of datatype Bound
type Bound struct {
	Data_Bound_
}

func (_this Bound) Get_() Data_Bound_ {
	return _this.Data_Bound_
}

type Data_Bound_ interface {
	isBound()
}

type CompanionStruct_Bound_ struct {
}

var Companion_Bound_ = CompanionStruct_Bound_{}

type Bound_Bound struct {
	Bid  _dafny.Sequence
	Sel  Sel
	Core BCore
}

func (Bound_Bound) isBound() {}

func (CompanionStruct_Bound_) Create_Bound_(Bid _dafny.Sequence, Sel Sel, Core BCore) Bound {
	return Bound{Bound_Bound{Bid, Sel, Core}}
}

func (_this Bound) Is_Bound() bool {
	_, ok := _this.Get_().(Bound_Bound)
	return ok
}

func (CompanionStruct_Bound_) Default() Bound {
	return Companion_Bound_.Create_Bound_(_dafny.EmptySeq, Companion_Sel_.Default(), Companion_BCore_.Default())
}

func (_this Bound) Dtor_bid() _dafny.Sequence {
	return _this.Get_().(Bound_Bound).Bid
}

func (_this Bound) Dtor_sel() Sel {
	return _this.Get_().(Bound_Bound).Sel
}

func (_this Bound) Dtor_core() BCore {
	return _this.Get_().(Bound_Bound).Core
}

func (_this Bound) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Bound_Bound:
		{
			return "GoalIr.Bound.Bound" + "(" + data.Bid.VerbatimString(true) + ", " + _dafny.String(data.Sel) + ", " + _dafny.String(data.Core) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Bound) Equals(other Bound) bool {
	switch data1 := _this.Get_().(type) {
	case Bound_Bound:
		{
			data2, ok := other.Get_().(Bound_Bound)
			return ok && data1.Bid.Equals(data2.Bid) && data1.Sel.Equals(data2.Sel) && data1.Core.Equals(data2.Core)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Bound) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Bound)
	return ok && _this.Equals(typed)
}

func Type_Bound_() _dafny.TypeDescriptor {
	return type_Bound_{}
}

type type_Bound_ struct {
}

func (_this type_Bound_) Default() interface{} {
	return Companion_Bound_.Default()
}

func (_this type_Bound_) String() string {
	return "GoalIr.Bound"
}
func (_this Bound) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Bound{}

// End of datatype Bound

// Definition of datatype Validity
type Validity struct {
	Data_Validity_
}

func (_this Validity) Get_() Data_Validity_ {
	return _this.Data_Validity_
}

type Data_Validity_ interface {
	isValidity()
}

type CompanionStruct_Validity_ struct {
}

var Companion_Validity_ = CompanionStruct_Validity_{}

type Validity_Validity struct {
	NotBefore _dafny.Int
	NotAfter  _dafny.Int
	MaxIdle   _dafny.Int
}

func (Validity_Validity) isValidity() {}

func (CompanionStruct_Validity_) Create_Validity_(NotBefore _dafny.Int, NotAfter _dafny.Int, MaxIdle _dafny.Int) Validity {
	return Validity{Validity_Validity{NotBefore, NotAfter, MaxIdle}}
}

func (_this Validity) Is_Validity() bool {
	_, ok := _this.Get_().(Validity_Validity)
	return ok
}

func (CompanionStruct_Validity_) Default() Validity {
	return Companion_Validity_.Create_Validity_(_dafny.Zero, _dafny.Zero, _dafny.Zero)
}

func (_this Validity) Dtor_notBefore() _dafny.Int {
	return _this.Get_().(Validity_Validity).NotBefore
}

func (_this Validity) Dtor_notAfter() _dafny.Int {
	return _this.Get_().(Validity_Validity).NotAfter
}

func (_this Validity) Dtor_maxIdle() _dafny.Int {
	return _this.Get_().(Validity_Validity).MaxIdle
}

func (_this Validity) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Validity_Validity:
		{
			return "GoalIr.Validity.Validity" + "(" + _dafny.String(data.NotBefore) + ", " + _dafny.String(data.NotAfter) + ", " + _dafny.String(data.MaxIdle) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Validity) Equals(other Validity) bool {
	switch data1 := _this.Get_().(type) {
	case Validity_Validity:
		{
			data2, ok := other.Get_().(Validity_Validity)
			return ok && data1.NotBefore.Cmp(data2.NotBefore) == 0 && data1.NotAfter.Cmp(data2.NotAfter) == 0 && data1.MaxIdle.Cmp(data2.MaxIdle) == 0
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Validity) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Validity)
	return ok && _this.Equals(typed)
}

func Type_Validity_() _dafny.TypeDescriptor {
	return type_Validity_{}
}

type type_Validity_ struct {
}

func (_this type_Validity_) Default() interface{} {
	return Companion_Validity_.Default()
}

func (_this type_Validity_) String() string {
	return "GoalIr.Validity"
}
func (_this Validity) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Validity{}

// End of datatype Validity

// Definition of datatype Delegation
type Delegation struct {
	Data_Delegation_
}

func (_this Delegation) Get_() Data_Delegation_ {
	return _this.Data_Delegation_
}

type Data_Delegation_ interface {
	isDelegation()
}

type CompanionStruct_Delegation_ struct {
}

var Companion_Delegation_ = CompanionStruct_Delegation_{}

type Delegation_Delegation struct {
	MaxDepth   _dafny.Int
	NarrowOnly bool
	MayTouch   _dafny.Sequence
}

func (Delegation_Delegation) isDelegation() {}

func (CompanionStruct_Delegation_) Create_Delegation_(MaxDepth _dafny.Int, NarrowOnly bool, MayTouch _dafny.Sequence) Delegation {
	return Delegation{Delegation_Delegation{MaxDepth, NarrowOnly, MayTouch}}
}

func (_this Delegation) Is_Delegation() bool {
	_, ok := _this.Get_().(Delegation_Delegation)
	return ok
}

func (CompanionStruct_Delegation_) Default() Delegation {
	return Companion_Delegation_.Create_Delegation_(_dafny.Zero, false, _dafny.EmptySeq)
}

func (_this Delegation) Dtor_maxDepth() _dafny.Int {
	return _this.Get_().(Delegation_Delegation).MaxDepth
}

func (_this Delegation) Dtor_narrowOnly() bool {
	return _this.Get_().(Delegation_Delegation).NarrowOnly
}

func (_this Delegation) Dtor_mayTouch() _dafny.Sequence {
	return _this.Get_().(Delegation_Delegation).MayTouch
}

func (_this Delegation) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Delegation_Delegation:
		{
			return "GoalIr.Delegation.Delegation" + "(" + _dafny.String(data.MaxDepth) + ", " + _dafny.String(data.NarrowOnly) + ", " + _dafny.String(data.MayTouch) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Delegation) Equals(other Delegation) bool {
	switch data1 := _this.Get_().(type) {
	case Delegation_Delegation:
		{
			data2, ok := other.Get_().(Delegation_Delegation)
			return ok && data1.MaxDepth.Cmp(data2.MaxDepth) == 0 && data1.NarrowOnly == data2.NarrowOnly && data1.MayTouch.Equals(data2.MayTouch)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Delegation) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Delegation)
	return ok && _this.Equals(typed)
}

func Type_Delegation_() _dafny.TypeDescriptor {
	return type_Delegation_{}
}

type type_Delegation_ struct {
}

func (_this type_Delegation_) Default() interface{} {
	return Companion_Delegation_.Default()
}

func (_this type_Delegation_) String() string {
	return "GoalIr.Delegation"
}
func (_this Delegation) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Delegation{}

// End of datatype Delegation

// Definition of datatype Hole
type Hole struct {
	Data_Hole_
}

func (_this Hole) Get_() Data_Hole_ {
	return _this.Data_Hole_
}

type Data_Hole_ interface {
	isHole()
}

type CompanionStruct_Hole_ struct {
}

var Companion_Hole_ = CompanionStruct_Hole_{}

type Hole_Hole struct {
	Hid     _dafny.Sequence
	Q       _dafny.Sequence
	Domain  _dafny.Sequence
	Affects _dafny.Sequence
	Global  bool
}

func (Hole_Hole) isHole() {}

func (CompanionStruct_Hole_) Create_Hole_(Hid _dafny.Sequence, Q _dafny.Sequence, Domain _dafny.Sequence, Affects _dafny.Sequence, Global bool) Hole {
	return Hole{Hole_Hole{Hid, Q, Domain, Affects, Global}}
}

func (_this Hole) Is_Hole() bool {
	_, ok := _this.Get_().(Hole_Hole)
	return ok
}

func (CompanionStruct_Hole_) Default() Hole {
	return Companion_Hole_.Create_Hole_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, false)
}

func (_this Hole) Dtor_hid() _dafny.Sequence {
	return _this.Get_().(Hole_Hole).Hid
}

func (_this Hole) Dtor_q() _dafny.Sequence {
	return _this.Get_().(Hole_Hole).Q
}

func (_this Hole) Dtor_domain() _dafny.Sequence {
	return _this.Get_().(Hole_Hole).Domain
}

func (_this Hole) Dtor_affects() _dafny.Sequence {
	return _this.Get_().(Hole_Hole).Affects
}

func (_this Hole) Dtor_global() bool {
	return _this.Get_().(Hole_Hole).Global
}

func (_this Hole) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Hole_Hole:
		{
			return "GoalIr.Hole.Hole" + "(" + data.Hid.VerbatimString(true) + ", " + data.Q.VerbatimString(true) + ", " + _dafny.String(data.Domain) + ", " + _dafny.String(data.Affects) + ", " + _dafny.String(data.Global) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Hole) Equals(other Hole) bool {
	switch data1 := _this.Get_().(type) {
	case Hole_Hole:
		{
			data2, ok := other.Get_().(Hole_Hole)
			return ok && data1.Hid.Equals(data2.Hid) && data1.Q.Equals(data2.Q) && data1.Domain.Equals(data2.Domain) && data1.Affects.Equals(data2.Affects) && data1.Global == data2.Global
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Hole) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Hole)
	return ok && _this.Equals(typed)
}

func Type_Hole_() _dafny.TypeDescriptor {
	return type_Hole_{}
}

type type_Hole_ struct {
}

func (_this type_Hole_) Default() interface{} {
	return Companion_Hole_.Default()
}

func (_this type_Hole_) String() string {
	return "GoalIr.Hole"
}
func (_this Hole) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Hole{}

// End of datatype Hole

// Definition of datatype Goal
type Goal struct {
	Data_Goal_
}

func (_this Goal) Get_() Data_Goal_ {
	return _this.Data_Goal_
}

type Data_Goal_ interface {
	isGoal()
}

type CompanionStruct_Goal_ struct {
}

var Companion_Goal_ = CompanionStruct_Goal_{}

type Goal_Goal struct {
	V           _dafny.Int
	Principal   _dafny.Sequence
	OntDigest   _dafny.Sequence
	NlDigest    _dafny.Sequence
	Sources     _dafny.Sequence
	Grants      _dafny.Sequence
	Prohibits   _dafny.Sequence
	Bounds      _dafny.Sequence
	Validity    Validity
	Deleg       Delegation
	EscalateOn  _dafny.Sequence
	WildcardAck _dafny.Sequence
	Holes       _dafny.Sequence
}

func (Goal_Goal) isGoal() {}

func (CompanionStruct_Goal_) Create_Goal_(V _dafny.Int, Principal _dafny.Sequence, OntDigest _dafny.Sequence, NlDigest _dafny.Sequence, Sources _dafny.Sequence, Grants _dafny.Sequence, Prohibits _dafny.Sequence, Bounds _dafny.Sequence, Validity Validity, Deleg Delegation, EscalateOn _dafny.Sequence, WildcardAck _dafny.Sequence, Holes _dafny.Sequence) Goal {
	return Goal{Goal_Goal{V, Principal, OntDigest, NlDigest, Sources, Grants, Prohibits, Bounds, Validity, Deleg, EscalateOn, WildcardAck, Holes}}
}

func (_this Goal) Is_Goal() bool {
	_, ok := _this.Get_().(Goal_Goal)
	return ok
}

func (CompanionStruct_Goal_) Default() Goal {
	return Companion_Goal_.Create_Goal_(_dafny.Zero, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, Companion_Validity_.Default(), Companion_Delegation_.Default(), _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this Goal) Dtor_v() _dafny.Int {
	return _this.Get_().(Goal_Goal).V
}

func (_this Goal) Dtor_principal() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).Principal
}

func (_this Goal) Dtor_ontDigest() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).OntDigest
}

func (_this Goal) Dtor_nlDigest() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).NlDigest
}

func (_this Goal) Dtor_sources() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).Sources
}

func (_this Goal) Dtor_grants() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).Grants
}

func (_this Goal) Dtor_prohibits() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).Prohibits
}

func (_this Goal) Dtor_bounds() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).Bounds
}

func (_this Goal) Dtor_validity() Validity {
	return _this.Get_().(Goal_Goal).Validity
}

func (_this Goal) Dtor_deleg() Delegation {
	return _this.Get_().(Goal_Goal).Deleg
}

func (_this Goal) Dtor_escalateOn() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).EscalateOn
}

func (_this Goal) Dtor_wildcardAck() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).WildcardAck
}

func (_this Goal) Dtor_holes() _dafny.Sequence {
	return _this.Get_().(Goal_Goal).Holes
}

func (_this Goal) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Goal_Goal:
		{
			return "GoalIr.Goal.Goal" + "(" + _dafny.String(data.V) + ", " + data.Principal.VerbatimString(true) + ", " + data.OntDigest.VerbatimString(true) + ", " + data.NlDigest.VerbatimString(true) + ", " + _dafny.String(data.Sources) + ", " + _dafny.String(data.Grants) + ", " + _dafny.String(data.Prohibits) + ", " + _dafny.String(data.Bounds) + ", " + _dafny.String(data.Validity) + ", " + _dafny.String(data.Deleg) + ", " + _dafny.String(data.EscalateOn) + ", " + _dafny.String(data.WildcardAck) + ", " + _dafny.String(data.Holes) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Goal) Equals(other Goal) bool {
	switch data1 := _this.Get_().(type) {
	case Goal_Goal:
		{
			data2, ok := other.Get_().(Goal_Goal)
			return ok && data1.V.Cmp(data2.V) == 0 && data1.Principal.Equals(data2.Principal) && data1.OntDigest.Equals(data2.OntDigest) && data1.NlDigest.Equals(data2.NlDigest) && data1.Sources.Equals(data2.Sources) && data1.Grants.Equals(data2.Grants) && data1.Prohibits.Equals(data2.Prohibits) && data1.Bounds.Equals(data2.Bounds) && data1.Validity.Equals(data2.Validity) && data1.Deleg.Equals(data2.Deleg) && data1.EscalateOn.Equals(data2.EscalateOn) && data1.WildcardAck.Equals(data2.WildcardAck) && data1.Holes.Equals(data2.Holes)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Goal) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Goal)
	return ok && _this.Equals(typed)
}

func Type_Goal_() _dafny.TypeDescriptor {
	return type_Goal_{}
}

type type_Goal_ struct {
}

func (_this type_Goal_) Default() interface{} {
	return Companion_Goal_.Default()
}

func (_this type_Goal_) String() string {
	return "GoalIr.Goal"
}
func (_this Goal) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Goal{}

// End of datatype Goal

// Definition of datatype ParamDecl
type ParamDecl struct {
	Data_ParamDecl_
}

func (_this ParamDecl) Get_() Data_ParamDecl_ {
	return _this.Data_ParamDecl_
}

type Data_ParamDecl_ interface {
	isParamDecl()
}

type CompanionStruct_ParamDecl_ struct {
}

var Companion_ParamDecl_ = CompanionStruct_ParamDecl_{}

type ParamDecl_ParamDecl struct {
	Path _dafny.Sequence
	Ty   Ty
}

func (ParamDecl_ParamDecl) isParamDecl() {}

func (CompanionStruct_ParamDecl_) Create_ParamDecl_(Path _dafny.Sequence, Ty Ty) ParamDecl {
	return ParamDecl{ParamDecl_ParamDecl{Path, Ty}}
}

func (_this ParamDecl) Is_ParamDecl() bool {
	_, ok := _this.Get_().(ParamDecl_ParamDecl)
	return ok
}

func (CompanionStruct_ParamDecl_) Default() ParamDecl {
	return Companion_ParamDecl_.Create_ParamDecl_(_dafny.EmptySeq, Companion_Ty_.Default())
}

func (_this ParamDecl) Dtor_path() _dafny.Sequence {
	return _this.Get_().(ParamDecl_ParamDecl).Path
}

func (_this ParamDecl) Dtor_ty() Ty {
	return _this.Get_().(ParamDecl_ParamDecl).Ty
}

func (_this ParamDecl) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case ParamDecl_ParamDecl:
		{
			return "GoalIr.ParamDecl.ParamDecl" + "(" + data.Path.VerbatimString(true) + ", " + _dafny.String(data.Ty) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this ParamDecl) Equals(other ParamDecl) bool {
	switch data1 := _this.Get_().(type) {
	case ParamDecl_ParamDecl:
		{
			data2, ok := other.Get_().(ParamDecl_ParamDecl)
			return ok && data1.Path.Equals(data2.Path) && data1.Ty.Equals(data2.Ty)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this ParamDecl) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(ParamDecl)
	return ok && _this.Equals(typed)
}

func Type_ParamDecl_() _dafny.TypeDescriptor {
	return type_ParamDecl_{}
}

type type_ParamDecl_ struct {
}

func (_this type_ParamDecl_) Default() interface{} {
	return Companion_ParamDecl_.Default()
}

func (_this type_ParamDecl_) String() string {
	return "GoalIr.ParamDecl"
}
func (_this ParamDecl) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = ParamDecl{}

// End of datatype ParamDecl

// Definition of datatype VerbDecl
type VerbDecl struct {
	Data_VerbDecl_
}

func (_this VerbDecl) Get_() Data_VerbDecl_ {
	return _this.Data_VerbDecl_
}

type Data_VerbDecl_ interface {
	isVerbDecl()
}

type CompanionStruct_VerbDecl_ struct {
}

var Companion_VerbDecl_ = CompanionStruct_VerbDecl_{}

type VerbDecl_VerbDecl struct {
	Verb   _dafny.Sequence
	Cls    _dafny.Sequence
	Params _dafny.Sequence
}

func (VerbDecl_VerbDecl) isVerbDecl() {}

func (CompanionStruct_VerbDecl_) Create_VerbDecl_(Verb _dafny.Sequence, Cls _dafny.Sequence, Params _dafny.Sequence) VerbDecl {
	return VerbDecl{VerbDecl_VerbDecl{Verb, Cls, Params}}
}

func (_this VerbDecl) Is_VerbDecl() bool {
	_, ok := _this.Get_().(VerbDecl_VerbDecl)
	return ok
}

func (CompanionStruct_VerbDecl_) Default() VerbDecl {
	return Companion_VerbDecl_.Create_VerbDecl_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this VerbDecl) Dtor_verb() _dafny.Sequence {
	return _this.Get_().(VerbDecl_VerbDecl).Verb
}

func (_this VerbDecl) Dtor_cls() _dafny.Sequence {
	return _this.Get_().(VerbDecl_VerbDecl).Cls
}

func (_this VerbDecl) Dtor_params() _dafny.Sequence {
	return _this.Get_().(VerbDecl_VerbDecl).Params
}

func (_this VerbDecl) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case VerbDecl_VerbDecl:
		{
			return "GoalIr.VerbDecl.VerbDecl" + "(" + data.Verb.VerbatimString(true) + ", " + data.Cls.VerbatimString(true) + ", " + _dafny.String(data.Params) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this VerbDecl) Equals(other VerbDecl) bool {
	switch data1 := _this.Get_().(type) {
	case VerbDecl_VerbDecl:
		{
			data2, ok := other.Get_().(VerbDecl_VerbDecl)
			return ok && data1.Verb.Equals(data2.Verb) && data1.Cls.Equals(data2.Cls) && data1.Params.Equals(data2.Params)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this VerbDecl) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(VerbDecl)
	return ok && _this.Equals(typed)
}

func Type_VerbDecl_() _dafny.TypeDescriptor {
	return type_VerbDecl_{}
}

type type_VerbDecl_ struct {
}

func (_this type_VerbDecl_) Default() interface{} {
	return Companion_VerbDecl_.Default()
}

func (_this type_VerbDecl_) String() string {
	return "GoalIr.VerbDecl"
}
func (_this VerbDecl) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = VerbDecl{}

// End of datatype VerbDecl

// Definition of datatype RelDecl
type RelDecl struct {
	Data_RelDecl_
}

func (_this RelDecl) Get_() Data_RelDecl_ {
	return _this.Data_RelDecl_
}

type Data_RelDecl_ interface {
	isRelDecl()
}

type CompanionStruct_RelDecl_ struct {
}

var Companion_RelDecl_ = CompanionStruct_RelDecl_{}

type RelDecl_RelDecl struct {
	Rel     _dafny.Sequence
	Anchor  _dafny.Sequence
	Members _dafny.Sequence
}

func (RelDecl_RelDecl) isRelDecl() {}

func (CompanionStruct_RelDecl_) Create_RelDecl_(Rel _dafny.Sequence, Anchor _dafny.Sequence, Members _dafny.Sequence) RelDecl {
	return RelDecl{RelDecl_RelDecl{Rel, Anchor, Members}}
}

func (_this RelDecl) Is_RelDecl() bool {
	_, ok := _this.Get_().(RelDecl_RelDecl)
	return ok
}

func (CompanionStruct_RelDecl_) Default() RelDecl {
	return Companion_RelDecl_.Create_RelDecl_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this RelDecl) Dtor_rel() _dafny.Sequence {
	return _this.Get_().(RelDecl_RelDecl).Rel
}

func (_this RelDecl) Dtor_anchor() _dafny.Sequence {
	return _this.Get_().(RelDecl_RelDecl).Anchor
}

func (_this RelDecl) Dtor_members() _dafny.Sequence {
	return _this.Get_().(RelDecl_RelDecl).Members
}

func (_this RelDecl) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case RelDecl_RelDecl:
		{
			return "GoalIr.RelDecl.RelDecl" + "(" + data.Rel.VerbatimString(true) + ", " + data.Anchor.VerbatimString(true) + ", " + _dafny.String(data.Members) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this RelDecl) Equals(other RelDecl) bool {
	switch data1 := _this.Get_().(type) {
	case RelDecl_RelDecl:
		{
			data2, ok := other.Get_().(RelDecl_RelDecl)
			return ok && data1.Rel.Equals(data2.Rel) && data1.Anchor.Equals(data2.Anchor) && data1.Members.Equals(data2.Members)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this RelDecl) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(RelDecl)
	return ok && _this.Equals(typed)
}

func Type_RelDecl_() _dafny.TypeDescriptor {
	return type_RelDecl_{}
}

type type_RelDecl_ struct {
}

func (_this type_RelDecl_) Default() interface{} {
	return Companion_RelDecl_.Default()
}

func (_this type_RelDecl_) String() string {
	return "GoalIr.RelDecl"
}
func (_this RelDecl) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = RelDecl{}

// End of datatype RelDecl

// Definition of datatype Ontology
type Ontology struct {
	Data_Ontology_
}

func (_this Ontology) Get_() Data_Ontology_ {
	return _this.Data_Ontology_
}

type Data_Ontology_ interface {
	isOntology()
}

type CompanionStruct_Ontology_ struct {
}

var Companion_Ontology_ = CompanionStruct_Ontology_{}

type Ontology_Ontology struct {
	Verbs _dafny.Sequence
	Rels  _dafny.Sequence
}

func (Ontology_Ontology) isOntology() {}

func (CompanionStruct_Ontology_) Create_Ontology_(Verbs _dafny.Sequence, Rels _dafny.Sequence) Ontology {
	return Ontology{Ontology_Ontology{Verbs, Rels}}
}

func (_this Ontology) Is_Ontology() bool {
	_, ok := _this.Get_().(Ontology_Ontology)
	return ok
}

func (CompanionStruct_Ontology_) Default() Ontology {
	return Companion_Ontology_.Create_Ontology_(_dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this Ontology) Dtor_verbs() _dafny.Sequence {
	return _this.Get_().(Ontology_Ontology).Verbs
}

func (_this Ontology) Dtor_rels() _dafny.Sequence {
	return _this.Get_().(Ontology_Ontology).Rels
}

func (_this Ontology) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Ontology_Ontology:
		{
			return "GoalIr.Ontology.Ontology" + "(" + _dafny.String(data.Verbs) + ", " + _dafny.String(data.Rels) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Ontology) Equals(other Ontology) bool {
	switch data1 := _this.Get_().(type) {
	case Ontology_Ontology:
		{
			data2, ok := other.Get_().(Ontology_Ontology)
			return ok && data1.Verbs.Equals(data2.Verbs) && data1.Rels.Equals(data2.Rels)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Ontology) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Ontology)
	return ok && _this.Equals(typed)
}

func Type_Ontology_() _dafny.TypeDescriptor {
	return type_Ontology_{}
}

type type_Ontology_ struct {
}

func (_this type_Ontology_) Default() interface{} {
	return Companion_Ontology_.Default()
}

func (_this type_Ontology_) String() string {
	return "GoalIr.Ontology"
}
func (_this Ontology) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Ontology{}

// End of datatype Ontology

// Definition of datatype Act
type Act struct {
	Data_Act_
}

func (_this Act) Get_() Data_Act_ {
	return _this.Data_Act_
}

type Data_Act_ interface {
	isAct()
}

type CompanionStruct_Act_ struct {
}

var Companion_Act_ = CompanionStruct_Act_{}

type Act_Act struct {
	Verb   _dafny.Sequence
	Res    _dafny.Sequence
	Params _dafny.Map
	T      _dafny.Int
	Sess   _dafny.Sequence
	Prin   _dafny.Sequence
	Org    _dafny.Sequence
	Agent  _dafny.Sequence
	Depth  _dafny.Int
}

func (Act_Act) isAct() {}

func (CompanionStruct_Act_) Create_Act_(Verb _dafny.Sequence, Res _dafny.Sequence, Params _dafny.Map, T _dafny.Int, Sess _dafny.Sequence, Prin _dafny.Sequence, Org _dafny.Sequence, Agent _dafny.Sequence, Depth _dafny.Int) Act {
	return Act{Act_Act{Verb, Res, Params, T, Sess, Prin, Org, Agent, Depth}}
}

func (_this Act) Is_Act() bool {
	_, ok := _this.Get_().(Act_Act)
	return ok
}

func (CompanionStruct_Act_) Default() Act {
	return Companion_Act_.Create_Act_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptyMap, _dafny.Zero, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.Zero)
}

func (_this Act) Dtor_verb() _dafny.Sequence {
	return _this.Get_().(Act_Act).Verb
}

func (_this Act) Dtor_res() _dafny.Sequence {
	return _this.Get_().(Act_Act).Res
}

func (_this Act) Dtor_params() _dafny.Map {
	return _this.Get_().(Act_Act).Params
}

func (_this Act) Dtor_t() _dafny.Int {
	return _this.Get_().(Act_Act).T
}

func (_this Act) Dtor_sess() _dafny.Sequence {
	return _this.Get_().(Act_Act).Sess
}

func (_this Act) Dtor_prin() _dafny.Sequence {
	return _this.Get_().(Act_Act).Prin
}

func (_this Act) Dtor_org() _dafny.Sequence {
	return _this.Get_().(Act_Act).Org
}

func (_this Act) Dtor_agent() _dafny.Sequence {
	return _this.Get_().(Act_Act).Agent
}

func (_this Act) Dtor_depth() _dafny.Int {
	return _this.Get_().(Act_Act).Depth
}

func (_this Act) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Act_Act:
		{
			return "GoalIr.Act.Act" + "(" + data.Verb.VerbatimString(true) + ", " + data.Res.VerbatimString(true) + ", " + _dafny.String(data.Params) + ", " + _dafny.String(data.T) + ", " + data.Sess.VerbatimString(true) + ", " + data.Prin.VerbatimString(true) + ", " + data.Org.VerbatimString(true) + ", " + data.Agent.VerbatimString(true) + ", " + _dafny.String(data.Depth) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Act) Equals(other Act) bool {
	switch data1 := _this.Get_().(type) {
	case Act_Act:
		{
			data2, ok := other.Get_().(Act_Act)
			return ok && data1.Verb.Equals(data2.Verb) && data1.Res.Equals(data2.Res) && data1.Params.Equals(data2.Params) && data1.T.Cmp(data2.T) == 0 && data1.Sess.Equals(data2.Sess) && data1.Prin.Equals(data2.Prin) && data1.Org.Equals(data2.Org) && data1.Agent.Equals(data2.Agent) && data1.Depth.Cmp(data2.Depth) == 0
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Act) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Act)
	return ok && _this.Equals(typed)
}

func Type_Act_() _dafny.TypeDescriptor {
	return type_Act_{}
}

type type_Act_ struct {
}

func (_this type_Act_) Default() interface{} {
	return Companion_Act_.Default()
}

func (_this type_Act_) String() string {
	return "GoalIr.Act"
}
func (_this Act) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Act{}

// End of datatype Act

// Definition of datatype Adm
type Adm struct {
	Data_Adm_
}

func (_this Adm) Get_() Data_Adm_ {
	return _this.Data_Adm_
}

type Data_Adm_ interface {
	isAdm()
}

type CompanionStruct_Adm_ struct {
}

var Companion_Adm_ = CompanionStruct_Adm_{}

type Adm_Adm struct {
	Gid _dafny.Sequence
	Act Act
}

func (Adm_Adm) isAdm() {}

func (CompanionStruct_Adm_) Create_Adm_(Gid _dafny.Sequence, Act Act) Adm {
	return Adm{Adm_Adm{Gid, Act}}
}

func (_this Adm) Is_Adm() bool {
	_, ok := _this.Get_().(Adm_Adm)
	return ok
}

func (CompanionStruct_Adm_) Default() Adm {
	return Companion_Adm_.Create_Adm_(_dafny.EmptySeq, Companion_Act_.Default())
}

func (_this Adm) Dtor_gid() _dafny.Sequence {
	return _this.Get_().(Adm_Adm).Gid
}

func (_this Adm) Dtor_act() Act {
	return _this.Get_().(Adm_Adm).Act
}

func (_this Adm) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Adm_Adm:
		{
			return "GoalIr.Adm.Adm" + "(" + data.Gid.VerbatimString(true) + ", " + _dafny.String(data.Act) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Adm) Equals(other Adm) bool {
	switch data1 := _this.Get_().(type) {
	case Adm_Adm:
		{
			data2, ok := other.Get_().(Adm_Adm)
			return ok && data1.Gid.Equals(data2.Gid) && data1.Act.Equals(data2.Act)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Adm) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Adm)
	return ok && _this.Equals(typed)
}

func Type_Adm_() _dafny.TypeDescriptor {
	return type_Adm_{}
}

type type_Adm_ struct {
}

func (_this type_Adm_) Default() interface{} {
	return Companion_Adm_.Default()
}

func (_this type_Adm_) String() string {
	return "GoalIr.Adm"
}
func (_this Adm) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Adm{}

// End of datatype Adm

// Definition of datatype Hist
type Hist struct {
	Data_Hist_
}

func (_this Hist) Get_() Data_Hist_ {
	return _this.Data_Hist_
}

type Data_Hist_ interface {
	isHist()
}

type CompanionStruct_Hist_ struct {
}

var Companion_Hist_ = CompanionStruct_Hist_{}

type Hist_Hist struct {
	Adms _dafny.Sequence
	Last _dafny.Int
	Aggs _dafny.Map
}

func (Hist_Hist) isHist() {}

func (CompanionStruct_Hist_) Create_Hist_(Adms _dafny.Sequence, Last _dafny.Int, Aggs _dafny.Map) Hist {
	return Hist{Hist_Hist{Adms, Last, Aggs}}
}

func (_this Hist) Is_Hist() bool {
	_, ok := _this.Get_().(Hist_Hist)
	return ok
}

func (CompanionStruct_Hist_) Default() Hist {
	return Companion_Hist_.Create_Hist_(_dafny.EmptySeq, _dafny.Zero, _dafny.EmptyMap)
}

func (_this Hist) Dtor_adms() _dafny.Sequence {
	return _this.Get_().(Hist_Hist).Adms
}

func (_this Hist) Dtor_last() _dafny.Int {
	return _this.Get_().(Hist_Hist).Last
}

func (_this Hist) Dtor_aggs() _dafny.Map {
	return _this.Get_().(Hist_Hist).Aggs
}

func (_this Hist) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Hist_Hist:
		{
			return "GoalIr.Hist.Hist" + "(" + _dafny.String(data.Adms) + ", " + _dafny.String(data.Last) + ", " + _dafny.String(data.Aggs) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Hist) Equals(other Hist) bool {
	switch data1 := _this.Get_().(type) {
	case Hist_Hist:
		{
			data2, ok := other.Get_().(Hist_Hist)
			return ok && data1.Adms.Equals(data2.Adms) && data1.Last.Cmp(data2.Last) == 0 && data1.Aggs.Equals(data2.Aggs)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Hist) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Hist)
	return ok && _this.Equals(typed)
}

func Type_Hist_() _dafny.TypeDescriptor {
	return type_Hist_{}
}

type type_Hist_ struct {
}

func (_this type_Hist_) Default() interface{} {
	return Companion_Hist_.Default()
}

func (_this type_Hist_) String() string {
	return "GoalIr.Hist"
}
func (_this Hist) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Hist{}

// End of datatype Hist

// Definition of datatype ResPat
type ResPat struct {
	Data_ResPat_
}

func (_this ResPat) Get_() Data_ResPat_ {
	return _this.Data_ResPat_
}

type Data_ResPat_ interface {
	isResPat()
}

type CompanionStruct_ResPat_ struct {
}

var Companion_ResPat_ = CompanionStruct_ResPat_{}

type ResPat_PStar struct {
}

func (ResPat_PStar) isResPat() {}

func (CompanionStruct_ResPat_) Create_PStar_() ResPat {
	return ResPat{ResPat_PStar{}}
}

func (_this ResPat) Is_PStar() bool {
	_, ok := _this.Get_().(ResPat_PStar)
	return ok
}

type ResPat_PSet struct {
	Ids _dafny.Sequence
}

func (ResPat_PSet) isResPat() {}

func (CompanionStruct_ResPat_) Create_PSet_(Ids _dafny.Sequence) ResPat {
	return ResPat{ResPat_PSet{Ids}}
}

func (_this ResPat) Is_PSet() bool {
	_, ok := _this.Get_().(ResPat_PSet)
	return ok
}

func (CompanionStruct_ResPat_) Default() ResPat {
	return Companion_ResPat_.Create_PStar_()
}

func (_this ResPat) Dtor_ids() _dafny.Sequence {
	return _this.Get_().(ResPat_PSet).Ids
}

func (_this ResPat) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case ResPat_PStar:
		{
			return "GoalIr.ResPat.PStar"
		}
	case ResPat_PSet:
		{
			return "GoalIr.ResPat.PSet" + "(" + _dafny.String(data.Ids) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this ResPat) Equals(other ResPat) bool {
	switch data1 := _this.Get_().(type) {
	case ResPat_PStar:
		{
			_, ok := other.Get_().(ResPat_PStar)
			return ok
		}
	case ResPat_PSet:
		{
			data2, ok := other.Get_().(ResPat_PSet)
			return ok && data1.Ids.Equals(data2.Ids)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this ResPat) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(ResPat)
	return ok && _this.Equals(typed)
}

func Type_ResPat_() _dafny.TypeDescriptor {
	return type_ResPat_{}
}

type type_ResPat_ struct {
}

func (_this type_ResPat_) Default() interface{} {
	return Companion_ResPat_.Default()
}

func (_this type_ResPat_) String() string {
	return "GoalIr.ResPat"
}
func (_this ResPat) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = ResPat{}

// End of datatype ResPat

// Definition of datatype LSel
type LSel struct {
	Data_LSel_
}

func (_this LSel) Get_() Data_LSel_ {
	return _this.Data_LSel_
}

type Data_LSel_ interface {
	isLSel()
}

type CompanionStruct_LSel_ struct {
}

var Companion_LSel_ = CompanionStruct_LSel_{}

type LSel_LSel struct {
	Gids  _dafny.Sequence
	Verbs _dafny.Sequence
}

func (LSel_LSel) isLSel() {}

func (CompanionStruct_LSel_) Create_LSel_(Gids _dafny.Sequence, Verbs _dafny.Sequence) LSel {
	return LSel{LSel_LSel{Gids, Verbs}}
}

func (_this LSel) Is_LSel() bool {
	_, ok := _this.Get_().(LSel_LSel)
	return ok
}

func (CompanionStruct_LSel_) Default() LSel {
	return Companion_LSel_.Create_LSel_(_dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this LSel) Dtor_gids() _dafny.Sequence {
	return _this.Get_().(LSel_LSel).Gids
}

func (_this LSel) Dtor_verbs() _dafny.Sequence {
	return _this.Get_().(LSel_LSel).Verbs
}

func (_this LSel) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case LSel_LSel:
		{
			return "GoalIr.LSel.LSel" + "(" + _dafny.String(data.Gids) + ", " + _dafny.String(data.Verbs) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this LSel) Equals(other LSel) bool {
	switch data1 := _this.Get_().(type) {
	case LSel_LSel:
		{
			data2, ok := other.Get_().(LSel_LSel)
			return ok && data1.Gids.Equals(data2.Gids) && data1.Verbs.Equals(data2.Verbs)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this LSel) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(LSel)
	return ok && _this.Equals(typed)
}

func Type_LSel_() _dafny.TypeDescriptor {
	return type_LSel_{}
}

type type_LSel_ struct {
}

func (_this type_LSel_) Default() interface{} {
	return Companion_LSel_.Default()
}

func (_this type_LSel_) String() string {
	return "GoalIr.LSel"
}
func (_this LSel) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = LSel{}

// End of datatype LSel
