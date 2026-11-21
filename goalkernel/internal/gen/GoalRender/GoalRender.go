// Package GoalRender
// Dafny module GoalRender compiled into Go

package GoalRender

import (
	m_GoalCompile "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/GoalCompile"
	m_GoalIr "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/GoalIr"
	m_GoalWitness "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/GoalWitness"
	m__System "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/System_"
	_dafny "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/dafny"
	os "os"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__
var _ m_GoalIr.Dummy__
var _ m_GoalCompile.Dummy__
var _ m_GoalWitness.Dummy__

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
	return "GoalRender.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) EncStr(s _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqOf(Companion_Tok_.Create_TS_(s))
}
func (_static *CompanionStruct_Default___) DecStr(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TS()) {
		return Companion_PR_.Create_Ok_(((ts).Select(0).(Tok)).Dtor_s(), (ts).Drop(1))
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncInt(i _dafny.Int) _dafny.Sequence {
	return _dafny.SeqOf(Companion_Tok_.Create_TI_(i))
}
func (_static *CompanionStruct_Default___) DecInt(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI()) {
		return Companion_PR_.Create_Ok_(((ts).Select(0).(Tok)).Dtor_i(), (ts).Drop(1))
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncBool(b bool) _dafny.Sequence {
	return _dafny.SeqOf(Companion_Tok_.Create_TI_((func() _dafny.Int {
		if b {
			return _dafny.One
		}
		return _dafny.Zero
	})()))
}
func (_static *CompanionStruct_Default___) DecBool(ts _dafny.Sequence) PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI())) && (((((ts).Select(0).(Tok)).Dtor_i()).Sign() == 0) || ((((ts).Select(0).(Tok)).Dtor_i()).Cmp(_dafny.One) == 0)) {
		return Companion_PR_.Create_Ok_((((ts).Select(0).(Tok)).Dtor_i()).Cmp(_dafny.One) == 0, (ts).Drop(1))
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncUnit(u m_GoalIr.Unit) _dafny.Sequence {
	var _source0 m_GoalIr.Unit = u
	_ = _source0
	{
		if _source0.Is_UMoney() {
			var _0_c _dafny.Sequence = _source0.Get_().(m_GoalIr.Unit_UMoney).Ccy
			_ = _0_c
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(300))), Companion_Default___.EncStr(_0_c))
		}
	}
	{
		if _source0.Is_UCount() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(301)))
		}
	}
	{
		if _source0.Is_UDuration() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(302)))
		}
	}
	{
		if _source0.Is_UInstant() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(303)))
		}
	}
	{
		if _source0.Is_UBytes() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(304)))
		}
	}
	{
		return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(305)))
	}
}
func (_static *CompanionStruct_Default___) DecUnit(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(300)) == 0 {
		var _source0 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_c _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _0_c
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Unit_.Create_UMoney_(_0_c), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(301)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Unit_.Create_UCount_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(302)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Unit_.Create_UDuration_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(303)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Unit_.Create_UInstant_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(304)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Unit_.Create_UBytes_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(305)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Unit_.Create_URatio_(), (ts).Drop(1))
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncQ(q m_GoalIr.Q) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncUnit((q).Dtor_u()), Companion_Default___.EncInt((q).Dtor_n()))
}
func (_static *CompanionStruct_Default___) DecQ(ts _dafny.Sequence) PR {
	var _source0 PR = Companion_Default___.DecUnit(ts)
	_ = _source0
	{
		if _source0.Is_Fail() {
			return Companion_PR_.Create_Fail_()
		}
	}
	{
		var _0_u m_GoalIr.Unit = _source0.Get_().(PR_Ok).V.(m_GoalIr.Unit)
		_ = _0_u
		var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
		_ = _1_r
		var _source1 PR = Companion_Default___.DecInt(_1_r)
		_ = _source1
		{
			if _source1.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _2_n _dafny.Int = _source1.Get_().(PR_Ok).V.(_dafny.Int)
			_ = _2_n
			var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
			_ = _3_r2
			return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Q_.Create_Q_(_0_u, _2_n), _3_r2)
		}
	}
}
func (_static *CompanionStruct_Default___) EncTy(t m_GoalIr.Ty) _dafny.Sequence {
	var _source0 m_GoalIr.Ty = t
	_ = _source0
	{
		if _source0.Is_TyQ() {
			var _0_u m_GoalIr.Unit = _source0.Get_().(m_GoalIr.Ty_TyQ).U
			_ = _0_u
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(310))), Companion_Default___.EncUnit(_0_u))
		}
	}
	{
		return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(311)))
	}
}
func (_static *CompanionStruct_Default___) DecTy(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(310)) == 0 {
		var _source0 PR = Companion_Default___.DecUnit((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_u m_GoalIr.Unit = _source0.Get_().(PR_Ok).V.(m_GoalIr.Unit)
				_ = _0_u
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Ty_.Create_TyQ_(_0_u), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(311)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Ty_.Create_TyS_(), (ts).Drop(1))
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncAtom(a m_GoalIr.Atom) _dafny.Sequence {
	var _source0 m_GoalIr.Atom = a
	_ = _source0
	{
		if _source0.Is_AQ() {
			var _0_q m_GoalIr.Q = _source0.Get_().(m_GoalIr.Atom_AQ).Q
			_ = _0_q
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(320))), Companion_Default___.EncQ(_0_q))
		}
	}
	{
		var _1_s _dafny.Sequence = _source0.Get_().(m_GoalIr.Atom_AS).S
		_ = _1_s
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(321))), Companion_Default___.EncStr(_1_s))
	}
}
func (_static *CompanionStruct_Default___) DecAtom(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(320)) == 0 {
		var _source0 PR = Companion_Default___.DecQ((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_q m_GoalIr.Q = _source0.Get_().(PR_Ok).V.(m_GoalIr.Q)
				_ = _0_q
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Atom_.Create_AQ_(_0_q), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(321)) == 0 {
		var _source1 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source1
		{
			if _source1.Is_Ok() {
				var _2_s _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_s
				var _3_r _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Atom_.Create_AS_(_2_s), _3_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncAtomsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncAtom((xs).Select(0).(m_GoalIr.Atom)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncAtoms(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncAtomsElems(xs))
}
func (_static *CompanionStruct_Default___) DecAtomsElems(ts _dafny.Sequence, n _dafny.Int) PR {
	if (n).Sign() == 0 {
		return Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 PR = Companion_Default___.DecAtom(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.Atom = _source0.Get_().(PR_Ok).V.(m_GoalIr.Atom)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r
			var _source1 PR = Companion_Default___.DecAtomsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				return Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecAtoms(ts _dafny.Sequence) PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI())) && ((((ts).Select(0).(Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecAtomsElems((ts).Drop(1), ((ts).Select(0).(Tok)).Dtor_i())
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncV(v m_GoalIr.V) _dafny.Sequence {
	var _source0 m_GoalIr.V = v
	_ = _source0
	{
		if _source0.Is_VQ() {
			var _0_q m_GoalIr.Q = _source0.Get_().(m_GoalIr.V_VQ).Q
			_ = _0_q
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(330))), Companion_Default___.EncQ(_0_q))
		}
	}
	{
		if _source0.Is_VS() {
			var _1_s _dafny.Sequence = _source0.Get_().(m_GoalIr.V_VS).S
			_ = _1_s
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(331))), Companion_Default___.EncStr(_1_s))
		}
	}
	{
		var _2_items _dafny.Sequence = _source0.Get_().(m_GoalIr.V_VSet).Items
		_ = _2_items
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(332))), Companion_Default___.EncAtoms(_2_items))
	}
}
func (_static *CompanionStruct_Default___) DecV(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(330)) == 0 {
		var _source0 PR = Companion_Default___.DecQ((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_q m_GoalIr.Q = _source0.Get_().(PR_Ok).V.(m_GoalIr.Q)
				_ = _0_q
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_V_.Create_VQ_(_0_q), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(331)) == 0 {
		var _source1 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source1
		{
			if _source1.Is_Ok() {
				var _2_s _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_s
				var _3_r _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_V_.Create_VS_(_2_s), _3_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(332)) == 0 {
		var _source2 PR = Companion_Default___.DecAtoms((ts).Drop(1))
		_ = _source2
		{
			if _source2.Is_Ok() {
				var _4_xs _dafny.Sequence = _source2.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _4_xs
				var _5_r _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
				_ = _5_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_V_.Create_VSet_(_4_xs), _5_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncTerm(t m_GoalIr.Term) _dafny.Sequence {
	var _source0 m_GoalIr.Term = t
	_ = _source0
	{
		if _source0.Is_Param() {
			var _0_p _dafny.Sequence = _source0.Get_().(m_GoalIr.Term_Param).Path
			_ = _0_p
			var _1_ty m_GoalIr.Ty = _source0.Get_().(m_GoalIr.Term_Param).Ty
			_ = _1_ty
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(340))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr(_0_p), Companion_Default___.EncTy(_1_ty)))
		}
	}
	{
		if _source0.Is_Lit() {
			var _2_v m_GoalIr.V = _source0.Get_().(m_GoalIr.Term_Lit).V
			_ = _2_v
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(341))), Companion_Default___.EncV(_2_v))
		}
	}
	{
		var _3_b _dafny.Sequence = _source0.Get_().(m_GoalIr.Term_HistAgg).Bid
		_ = _3_b
		var _4_u m_GoalIr.Unit = _source0.Get_().(m_GoalIr.Term_HistAgg).U
		_ = _4_u
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(342))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr(_3_b), Companion_Default___.EncUnit(_4_u)))
	}
}
func (_static *CompanionStruct_Default___) DecTerm(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(340)) == 0 {
		var _source0 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_p _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _0_p
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecTy(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_ty m_GoalIr.Ty = _source1.Get_().(PR_Ok).V.(m_GoalIr.Ty)
				_ = _2_ty
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Term_.Create_Param_(_0_p, _2_ty), _3_r2)
			}
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(341)) == 0 {
		var _source2 PR = Companion_Default___.DecV((ts).Drop(1))
		_ = _source2
		{
			if _source2.Is_Ok() {
				var _4_v m_GoalIr.V = _source2.Get_().(PR_Ok).V.(m_GoalIr.V)
				_ = _4_v
				var _5_r _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
				_ = _5_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Term_.Create_Lit_(_4_v), _5_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(342)) == 0 {
		var _source3 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source3
		{
			if _source3.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _6_b _dafny.Sequence = _source3.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _6_b
			var _7_r1 _dafny.Sequence = _source3.Get_().(PR_Ok).Rest
			_ = _7_r1
			var _source4 PR = Companion_Default___.DecUnit(_7_r1)
			_ = _source4
			{
				if _source4.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _8_u m_GoalIr.Unit = _source4.Get_().(PR_Ok).V.(m_GoalIr.Unit)
				_ = _8_u
				var _9_r2 _dafny.Sequence = _source4.Get_().(PR_Ok).Rest
				_ = _9_r2
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Term_.Create_HistAgg_(_6_b, _8_u), _9_r2)
			}
		}
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) OpIdx(op m_GoalIr.Op) _dafny.Int {
	var _source0 m_GoalIr.Op = op
	_ = _source0
	{
		if _source0.Is_Eq() {
			return _dafny.Zero
		}
	}
	{
		if _source0.Is_Ne() {
			return _dafny.One
		}
	}
	{
		if _source0.Is_Lt() {
			return _dafny.IntOfInt64(2)
		}
	}
	{
		if _source0.Is_Lte() {
			return _dafny.IntOfInt64(3)
		}
	}
	{
		if _source0.Is_Gt() {
			return _dafny.IntOfInt64(4)
		}
	}
	{
		if _source0.Is_Gte() {
			return _dafny.IntOfInt64(5)
		}
	}
	{
		if _source0.Is_In() {
			return _dafny.IntOfInt64(6)
		}
	}
	{
		return _dafny.IntOfInt64(7)
	}
}
func (_static *CompanionStruct_Default___) EncOp(op m_GoalIr.Op) _dafny.Sequence {
	return _dafny.SeqOf(Companion_Tok_.Create_TKw_((_dafny.IntOfInt64(350)).Plus(Companion_Default___.OpIdx(op))))
}
func (_static *CompanionStruct_Default___) DecOp(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(350)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Op_.Create_Eq_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(351)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Op_.Create_Ne_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(352)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Op_.Create_Lt_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(353)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Op_.Create_Lte_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(354)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Op_.Create_Gt_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(355)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Op_.Create_Gte_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(356)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Op_.Create_In_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(357)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Op_.Create_Nin_(), (ts).Drop(1))
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncCond(c m_GoalIr.Cond) _dafny.Sequence {
	var _source0 m_GoalIr.Cond = c
	_ = _source0
	{
		if _source0.Is_CTrue() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(360)))
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
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(361))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncOp(_0_op), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncTerm(_1_l), Companion_Default___.EncTerm(_2_r))))
		}
	}
	{
		if _source0.Is_And() {
			var _3_x m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_And).A
			_ = _3_x
			var _4_y m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_And).B
			_ = _4_y
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(362))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncCond(_3_x), Companion_Default___.EncCond(_4_y)))
		}
	}
	{
		if _source0.Is_Or() {
			var _5_x m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_Or).A
			_ = _5_x
			var _6_y m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_Or).B
			_ = _6_y
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(363))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncCond(_5_x), Companion_Default___.EncCond(_6_y)))
		}
	}
	{
		var _7_x m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_Not).C
		_ = _7_x
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(364))), Companion_Default___.EncCond(_7_x))
	}
}
func (_static *CompanionStruct_Default___) DecCond(ts _dafny.Sequence, fuel _dafny.Int) PR {
	if (((fuel).Sign() == 0) || ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0)) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(360)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Cond_.Create_CTrue_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(361)) == 0 {
		var _source0 PR = Companion_Default___.DecOp((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_op m_GoalIr.Op = _source0.Get_().(PR_Ok).V.(m_GoalIr.Op)
			_ = _0_op
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecTerm(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_l m_GoalIr.Term = _source1.Get_().(PR_Ok).V.(m_GoalIr.Term)
				_ = _2_l
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				var _source2 PR = Companion_Default___.DecTerm(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_r m_GoalIr.Term = _source2.Get_().(PR_Ok).V.(m_GoalIr.Term)
					_ = _4_r
					var _5_r3 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
					_ = _5_r3
					return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Cond_.Create_Cmp_(_0_op, _2_l, _4_r), _5_r3)
				}
			}
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(362)) == 0 {
		var _source3 PR = Companion_Default___.DecCond((ts).Drop(1), (fuel).Minus(_dafny.One))
		_ = _source3
		{
			if _source3.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _6_x m_GoalIr.Cond = _source3.Get_().(PR_Ok).V.(m_GoalIr.Cond)
			_ = _6_x
			var _7_r1 _dafny.Sequence = _source3.Get_().(PR_Ok).Rest
			_ = _7_r1
			var _source4 PR = Companion_Default___.DecCond(_7_r1, (fuel).Minus(_dafny.One))
			_ = _source4
			{
				if _source4.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _8_y m_GoalIr.Cond = _source4.Get_().(PR_Ok).V.(m_GoalIr.Cond)
				_ = _8_y
				var _9_r2 _dafny.Sequence = _source4.Get_().(PR_Ok).Rest
				_ = _9_r2
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Cond_.Create_And_(_6_x, _8_y), _9_r2)
			}
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(363)) == 0 {
		var _source5 PR = Companion_Default___.DecCond((ts).Drop(1), (fuel).Minus(_dafny.One))
		_ = _source5
		{
			if _source5.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _10_x m_GoalIr.Cond = _source5.Get_().(PR_Ok).V.(m_GoalIr.Cond)
			_ = _10_x
			var _11_r1 _dafny.Sequence = _source5.Get_().(PR_Ok).Rest
			_ = _11_r1
			var _source6 PR = Companion_Default___.DecCond(_11_r1, (fuel).Minus(_dafny.One))
			_ = _source6
			{
				if _source6.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _12_y m_GoalIr.Cond = _source6.Get_().(PR_Ok).V.(m_GoalIr.Cond)
				_ = _12_y
				var _13_r2 _dafny.Sequence = _source6.Get_().(PR_Ok).Rest
				_ = _13_r2
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Cond_.Create_Or_(_10_x, _12_y), _13_r2)
			}
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(364)) == 0 {
		var _source7 PR = Companion_Default___.DecCond((ts).Drop(1), (fuel).Minus(_dafny.One))
		_ = _source7
		{
			if _source7.Is_Ok() {
				var _14_x m_GoalIr.Cond = _source7.Get_().(PR_Ok).V.(m_GoalIr.Cond)
				_ = _14_x
				var _15_r _dafny.Sequence = _source7.Get_().(PR_Ok).Rest
				_ = _15_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Cond_.Create_Not_(_14_x), _15_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) DecCondTop(ts _dafny.Sequence) PR {
	return Companion_Default___.DecCond(ts, _dafny.IntOfUint32((ts).Cardinality()))
}
func (_static *CompanionStruct_Default___) Depth(c m_GoalIr.Cond) _dafny.Int {
	var _source0 m_GoalIr.Cond = c
	_ = _source0
	{
		if _source0.Is_CTrue() {
			return _dafny.One
		}
	}
	{
		if _source0.Is_Cmp() {
			return _dafny.One
		}
	}
	{
		if _source0.Is_And() {
			var _0_x m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_And).A
			_ = _0_x
			var _1_y m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_And).B
			_ = _1_y
			return (_dafny.One).Plus((func() _dafny.Int {
				if (Companion_Default___.Depth(_0_x)).Cmp(Companion_Default___.Depth(_1_y)) >= 0 {
					return Companion_Default___.Depth(_0_x)
				}
				return Companion_Default___.Depth(_1_y)
			})())
		}
	}
	{
		if _source0.Is_Or() {
			var _2_x m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_Or).A
			_ = _2_x
			var _3_y m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_Or).B
			_ = _3_y
			return (_dafny.One).Plus((func() _dafny.Int {
				if (Companion_Default___.Depth(_2_x)).Cmp(Companion_Default___.Depth(_3_y)) >= 0 {
					return Companion_Default___.Depth(_2_x)
				}
				return Companion_Default___.Depth(_3_y)
			})())
		}
	}
	{
		var _4_x m_GoalIr.Cond = _source0.Get_().(m_GoalIr.Cond_Not).C
		_ = _4_x
		return (_dafny.One).Plus(Companion_Default___.Depth(_4_x))
	}
}
func (_static *CompanionStruct_Default___) EncPart(p m_GoalIr.ResPart) _dafny.Sequence {
	var _source0 m_GoalIr.ResPart = p
	_ = _source0
	{
		if _source0.Is_PartExact() {
			var _0_id _dafny.Sequence = _source0.Get_().(m_GoalIr.ResPart_PartExact).Id
			_ = _0_id
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(375))), Companion_Default___.EncStr(_0_id))
		}
	}
	{
		if _source0.Is_PartOneOf() {
			var _1_ids _dafny.Sequence = _source0.Get_().(m_GoalIr.ResPart_PartOneOf).Ids
			_ = _1_ids
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(376))), Companion_Default___.EncStrs(_1_ids))
		}
	}
	{
		var _2_rel _dafny.Sequence = _source0.Get_().(m_GoalIr.ResPart_PartRelated).Rel
		_ = _2_rel
		var _3_anchor _dafny.Sequence = _source0.Get_().(m_GoalIr.ResPart_PartRelated).Anchor
		_ = _3_anchor
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(377))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr(_2_rel), Companion_Default___.EncStr(_3_anchor)))
	}
}
func (_static *CompanionStruct_Default___) DecPart(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(375)) == 0 {
		var _source0 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_id _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _0_id
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ResPart_.Create_PartExact_(_0_id), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(376)) == 0 {
		var _source1 PR = Companion_Default___.DecStrs((ts).Drop(1))
		_ = _source1
		{
			if _source1.Is_Ok() {
				var _2_ids _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_ids
				var _3_r _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ResPart_.Create_PartOneOf_(_2_ids), _3_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(377)) == 0 {
		var _source2 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source2
		{
			if _source2.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _4_rel _dafny.Sequence = _source2.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _4_rel
			var _5_r1 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
			_ = _5_r1
			var _source3 PR = Companion_Default___.DecStr(_5_r1)
			_ = _source3
			{
				if _source3.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _6_anchor _dafny.Sequence = _source3.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _6_anchor
				var _7_r2 _dafny.Sequence = _source3.Get_().(PR_Ok).Rest
				_ = _7_r2
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ResPart_.Create_PartRelated_(_4_rel, _6_anchor), _7_r2)
			}
		}
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncPartsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncPart((xs).Select(0).(m_GoalIr.ResPart)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncParts(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncPartsElems(xs))
}
func (_static *CompanionStruct_Default___) DecPartsElems(ts _dafny.Sequence, n _dafny.Int) PR {
	if (n).Sign() == 0 {
		return Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 PR = Companion_Default___.DecPart(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.ResPart = _source0.Get_().(PR_Ok).V.(m_GoalIr.ResPart)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r
			var _source1 PR = Companion_Default___.DecPartsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				return Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecParts(ts _dafny.Sequence) PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI())) && ((((ts).Select(0).(Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecPartsElems((ts).Drop(1), ((ts).Select(0).(Tok)).Dtor_i())
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncResSel(s m_GoalIr.ResSel) _dafny.Sequence {
	var _source0 m_GoalIr.ResSel = s
	_ = _source0
	{
		if _source0.Is_Exact() {
			var _0_id _dafny.Sequence = _source0.Get_().(m_GoalIr.ResSel_Exact).Id
			_ = _0_id
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(370))), Companion_Default___.EncStr(_0_id))
		}
	}
	{
		if _source0.Is_OneOf() {
			var _1_ids _dafny.Sequence = _source0.Get_().(m_GoalIr.ResSel_OneOf).Ids
			_ = _1_ids
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(371))), Companion_Default___.EncStrs(_1_ids))
		}
	}
	{
		if _source0.Is_Related() {
			var _2_rel _dafny.Sequence = _source0.Get_().(m_GoalIr.ResSel_Related).Rel
			_ = _2_rel
			var _3_anchor _dafny.Sequence = _source0.Get_().(m_GoalIr.ResSel_Related).Anchor
			_ = _3_anchor
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(372))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr(_2_rel), Companion_Default___.EncStr(_3_anchor)))
		}
	}
	{
		if _source0.Is_AnyRes() {
			var _4_reason _dafny.Sequence = _source0.Get_().(m_GoalIr.ResSel_AnyRes).Reason
			_ = _4_reason
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(373))), Companion_Default___.EncStr(_4_reason))
		}
	}
	{
		var _5_ps _dafny.Sequence = _source0.Get_().(m_GoalIr.ResSel_AllOf).Parts
		_ = _5_ps
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(374))), Companion_Default___.EncParts(_5_ps))
	}
}
func (_static *CompanionStruct_Default___) DecResSel(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(370)) == 0 {
		var _source0 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_id _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _0_id
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ResSel_.Create_Exact_(_0_id), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(371)) == 0 {
		var _source1 PR = Companion_Default___.DecStrs((ts).Drop(1))
		_ = _source1
		{
			if _source1.Is_Ok() {
				var _2_ids _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_ids
				var _3_r _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ResSel_.Create_OneOf_(_2_ids), _3_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(372)) == 0 {
		var _source2 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source2
		{
			if _source2.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _4_rel _dafny.Sequence = _source2.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _4_rel
			var _5_r1 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
			_ = _5_r1
			var _source3 PR = Companion_Default___.DecStr(_5_r1)
			_ = _source3
			{
				if _source3.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _6_anchor _dafny.Sequence = _source3.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _6_anchor
				var _7_r2 _dafny.Sequence = _source3.Get_().(PR_Ok).Rest
				_ = _7_r2
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ResSel_.Create_Related_(_4_rel, _6_anchor), _7_r2)
			}
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(373)) == 0 {
		var _source4 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source4
		{
			if _source4.Is_Ok() {
				var _8_reason _dafny.Sequence = _source4.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _8_reason
				var _9_r _dafny.Sequence = _source4.Get_().(PR_Ok).Rest
				_ = _9_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ResSel_.Create_AnyRes_(_8_reason), _9_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(374)) == 0 {
		var _source5 PR = Companion_Default___.DecParts((ts).Drop(1))
		_ = _source5
		{
			if _source5.Is_Ok() {
				var _10_ps _dafny.Sequence = _source5.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _10_ps
				var _11_r _dafny.Sequence = _source5.Get_().(PR_Ok).Rest
				_ = _11_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ResSel_.Create_AllOf_(_10_ps), _11_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncGrant(g m_GoalIr.Grant) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(380))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr((g).Dtor_gid()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr((g).Dtor_verb()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncResSel((g).Dtor_res()), Companion_Default___.EncCond((g).Dtor_cond())))))
}
func (_static *CompanionStruct_Default___) DecGrant(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(Tok)).Equals(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(380)))) {
		return Companion_PR_.Create_Fail_()
	} else {
		var _source0 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_gid _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _0_gid
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecStr(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_verb _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_verb
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				var _source2 PR = Companion_Default___.DecResSel(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_res m_GoalIr.ResSel = _source2.Get_().(PR_Ok).V.(m_GoalIr.ResSel)
					_ = _4_res
					var _5_r3 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
					_ = _5_r3
					var _source3 PR = Companion_Default___.DecCondTop(_5_r3)
					_ = _source3
					{
						if _source3.Is_Fail() {
							return Companion_PR_.Create_Fail_()
						}
					}
					{
						var _6_c m_GoalIr.Cond = _source3.Get_().(PR_Ok).V.(m_GoalIr.Cond)
						_ = _6_c
						var _7_r4 _dafny.Sequence = _source3.Get_().(PR_Ok).Rest
						_ = _7_r4
						return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Grant_.Create_Grant_(_0_gid, _2_verb, _4_res, _6_c), _7_r4)
					}
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) EncProhTarget(t m_GoalIr.ProhTarget) _dafny.Sequence {
	var _source0 m_GoalIr.ProhTarget = t
	_ = _source0
	{
		if _source0.Is_PVerb() {
			var _0_v _dafny.Sequence = _source0.Get_().(m_GoalIr.ProhTarget_PVerb).Verb
			_ = _0_v
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(390))), Companion_Default___.EncStr(_0_v))
		}
	}
	{
		var _1_c _dafny.Sequence = _source0.Get_().(m_GoalIr.ProhTarget_PEffect).Cls
		_ = _1_c
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(391))), Companion_Default___.EncStr(_1_c))
	}
}
func (_static *CompanionStruct_Default___) DecProhTarget(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(390)) == 0 {
		var _source0 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_v _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _0_v
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ProhTarget_.Create_PVerb_(_0_v), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(391)) == 0 {
		var _source1 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source1
		{
			if _source1.Is_Ok() {
				var _2_c _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_c
				var _3_r _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_ProhTarget_.Create_PEffect_(_2_c), _3_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncProhibit(p m_GoalIr.Prohibit) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(392))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr((p).Dtor_pid()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncProhTarget((p).Dtor_target()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncResSel((p).Dtor_res()), Companion_Default___.EncCond((p).Dtor_cond())))))
}
func (_static *CompanionStruct_Default___) DecProhibit(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(Tok)).Equals(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(392)))) {
		return Companion_PR_.Create_Fail_()
	} else {
		var _source0 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_pid _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _0_pid
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecProhTarget(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_tg m_GoalIr.ProhTarget = _source1.Get_().(PR_Ok).V.(m_GoalIr.ProhTarget)
				_ = _2_tg
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				var _source2 PR = Companion_Default___.DecResSel(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_res m_GoalIr.ResSel = _source2.Get_().(PR_Ok).V.(m_GoalIr.ResSel)
					_ = _4_res
					var _5_r3 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
					_ = _5_r3
					var _source3 PR = Companion_Default___.DecCondTop(_5_r3)
					_ = _source3
					{
						if _source3.Is_Fail() {
							return Companion_PR_.Create_Fail_()
						}
					}
					{
						var _6_c m_GoalIr.Cond = _source3.Get_().(PR_Ok).V.(m_GoalIr.Cond)
						_ = _6_c
						var _7_r4 _dafny.Sequence = _source3.Get_().(PR_Ok).Rest
						_ = _7_r4
						return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Prohibit_.Create_Prohibit_(_0_pid, _2_tg, _4_res, _6_c), _7_r4)
					}
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) EncAgg(a m_GoalIr.Agg) _dafny.Sequence {
	var _source0 m_GoalIr.Agg = a
	_ = _source0
	{
		if _source0.Is_ACount() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(400)))
		}
	}
	{
		if _source0.Is_ASum() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(401)))
		}
	}
	{
		if _source0.Is_AMax() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(402)))
		}
	}
	{
		return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(403)))
	}
}
func (_static *CompanionStruct_Default___) DecAgg(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(400)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Agg_.Create_ACount_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(401)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Agg_.Create_ASum_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(402)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Agg_.Create_AMax_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(403)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Agg_.Create_ADistinct_(), (ts).Drop(1))
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncSel(s m_GoalIr.Sel) _dafny.Sequence {
	var _source0 m_GoalIr.Sel = s
	_ = _source0
	{
		if _source0.Is_SelGids() {
			var _0_g _dafny.Sequence = _source0.Get_().(m_GoalIr.Sel_SelGids).Gids
			_ = _0_g
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(410))), Companion_Default___.EncStrs(_0_g))
		}
	}
	{
		var _1_c _dafny.Sequence = _source0.Get_().(m_GoalIr.Sel_SelEffect).Cls
		_ = _1_c
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(411))), Companion_Default___.EncStr(_1_c))
	}
}
func (_static *CompanionStruct_Default___) DecSel(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(410)) == 0 {
		var _source0 PR = Companion_Default___.DecStrs((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_g _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _0_g
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Sel_.Create_SelGids_(_0_g), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(411)) == 0 {
		var _source1 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source1
		{
			if _source1.Is_Ok() {
				var _2_c _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_c
				var _3_r _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Sel_.Create_SelEffect_(_2_c), _3_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncWindow(w m_GoalIr.Window) _dafny.Sequence {
	var _source0 m_GoalIr.Window = w
	_ = _source0
	{
		if _source0.Is_WTask() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(420)))
		}
	}
	{
		if _source0.Is_WSliding() {
			var _0_ms _dafny.Int = _source0.Get_().(m_GoalIr.Window_WSliding).Ms
			_ = _0_ms
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(421))), Companion_Default___.EncInt(_0_ms))
		}
	}
	{
		if _source0.Is_WPeriod() {
			var _1_ms _dafny.Int = _source0.Get_().(m_GoalIr.Window_WPeriod).Ms
			_ = _1_ms
			var _2_t0 _dafny.Int = _source0.Get_().(m_GoalIr.Window_WPeriod).T0
			_ = _2_t0
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(422))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncInt(_1_ms), Companion_Default___.EncInt(_2_t0)))
		}
	}
	{
		return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(423)))
	}
}
func (_static *CompanionStruct_Default___) DecWindow(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(420)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Window_.Create_WTask_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(421)) == 0 {
		var _source0 PR = Companion_Default___.DecInt((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_ms _dafny.Int = _source0.Get_().(PR_Ok).V.(_dafny.Int)
				_ = _0_ms
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Window_.Create_WSliding_(_0_ms), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(422)) == 0 {
		var _source1 PR = Companion_Default___.DecInt((ts).Drop(1))
		_ = _source1
		{
			if _source1.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _2_ms _dafny.Int = _source1.Get_().(PR_Ok).V.(_dafny.Int)
			_ = _2_ms
			var _3_r1 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
			_ = _3_r1
			var _source2 PR = Companion_Default___.DecInt(_3_r1)
			_ = _source2
			{
				if _source2.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _4_t0 _dafny.Int = _source2.Get_().(PR_Ok).V.(_dafny.Int)
				_ = _4_t0
				var _5_r2 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
				_ = _5_r2
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Window_.Create_WPeriod_(_2_ms, _4_t0), _5_r2)
			}
		}
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(423)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Window_.Create_WLifetime_(), (ts).Drop(1))
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncScope(s m_GoalIr.Scope) _dafny.Sequence {
	var _source0 m_GoalIr.Scope = s
	_ = _source0
	{
		if _source0.Is_SSession() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(430)))
		}
	}
	{
		if _source0.Is_SPrincipal() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(431)))
		}
	}
	{
		if _source0.Is_SOrg() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(432)))
		}
	}
	{
		var _0_a _dafny.Sequence = _source0.Get_().(m_GoalIr.Scope_SFleet).Agents
		_ = _0_a
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(433))), Companion_Default___.EncStrs(_0_a))
	}
}
func (_static *CompanionStruct_Default___) DecScope(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(430)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Scope_.Create_SSession_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(431)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Scope_.Create_SPrincipal_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(432)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Scope_.Create_SOrg_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(433)) == 0 {
		var _source0 PR = Companion_Default___.DecStrs((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Ok() {
				var _0_a _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _0_a
				var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
				_ = _1_r
				return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Scope_.Create_SFleet_(_0_a), _1_r)
			}
		}
		{
			return Companion_PR_.Create_Fail_()
		}
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncOnExceed(o m_GoalIr.OnExceed) _dafny.Sequence {
	var _source0 m_GoalIr.OnExceed = o
	_ = _source0
	{
		if _source0.Is_OnDeny() {
			return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(440)))
		}
	}
	{
		return _dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(441)))
	}
}
func (_static *CompanionStruct_Default___) DecOnExceed(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!(((ts).Select(0).(Tok)).Is_TKw())) {
		return Companion_PR_.Create_Fail_()
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(440)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_OnExceed_.Create_OnDeny_(), (ts).Drop(1))
	} else if (((ts).Select(0).(Tok)).Dtor_k()).Cmp(_dafny.IntOfInt64(441)) == 0 {
		return Companion_PR_.Create_Ok_(m_GoalIr.Companion_OnExceed_.Create_OnEscalate_(), (ts).Drop(1))
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncBCore(b m_GoalIr.BCore) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(450))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncAgg((b).Dtor_agg()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncTerm((b).Dtor_value()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr((b).Dtor_key()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncWindow((b).Dtor_window()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncScope((b).Dtor_scope()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncQ((b).Dtor_cap()), Companion_Default___.EncOnExceed((b).Dtor_onExceed()))))))))
}
func (_static *CompanionStruct_Default___) DecBCore(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(Tok)).Equals(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(450)))) {
		return Companion_PR_.Create_Fail_()
	} else {
		var _source0 PR = Companion_Default___.DecAgg((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_agg m_GoalIr.Agg = _source0.Get_().(PR_Ok).V.(m_GoalIr.Agg)
			_ = _0_agg
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecTerm(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_value m_GoalIr.Term = _source1.Get_().(PR_Ok).V.(m_GoalIr.Term)
				_ = _2_value
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				var _source2 PR = Companion_Default___.DecStr(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_key _dafny.Sequence = _source2.Get_().(PR_Ok).V.(_dafny.Sequence)
					_ = _4_key
					var _5_r3 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
					_ = _5_r3
					var _source3 PR = Companion_Default___.DecWindow(_5_r3)
					_ = _source3
					{
						if _source3.Is_Fail() {
							return Companion_PR_.Create_Fail_()
						}
					}
					{
						var _6_window m_GoalIr.Window = _source3.Get_().(PR_Ok).V.(m_GoalIr.Window)
						_ = _6_window
						var _7_r4 _dafny.Sequence = _source3.Get_().(PR_Ok).Rest
						_ = _7_r4
						var _source4 PR = Companion_Default___.DecScope(_7_r4)
						_ = _source4
						{
							if _source4.Is_Fail() {
								return Companion_PR_.Create_Fail_()
							}
						}
						{
							var _8_scope m_GoalIr.Scope = _source4.Get_().(PR_Ok).V.(m_GoalIr.Scope)
							_ = _8_scope
							var _9_r5 _dafny.Sequence = _source4.Get_().(PR_Ok).Rest
							_ = _9_r5
							var _source5 PR = Companion_Default___.DecQ(_9_r5)
							_ = _source5
							{
								if _source5.Is_Fail() {
									return Companion_PR_.Create_Fail_()
								}
							}
							{
								var _10_cap m_GoalIr.Q = _source5.Get_().(PR_Ok).V.(m_GoalIr.Q)
								_ = _10_cap
								var _11_r6 _dafny.Sequence = _source5.Get_().(PR_Ok).Rest
								_ = _11_r6
								var _source6 PR = Companion_Default___.DecOnExceed(_11_r6)
								_ = _source6
								{
									if _source6.Is_Fail() {
										return Companion_PR_.Create_Fail_()
									}
								}
								{
									var _12_oe m_GoalIr.OnExceed = _source6.Get_().(PR_Ok).V.(m_GoalIr.OnExceed)
									_ = _12_oe
									var _13_r7 _dafny.Sequence = _source6.Get_().(PR_Ok).Rest
									_ = _13_r7
									return Companion_PR_.Create_Ok_(m_GoalIr.Companion_BCore_.Create_BCore_(_0_agg, _2_value, _4_key, _6_window, _8_scope, _10_cap, _12_oe), _13_r7)
								}
							}
						}
					}
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) EncBound(b m_GoalIr.Bound) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(451))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr((b).Dtor_bid()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncSel((b).Dtor_sel()), Companion_Default___.EncBCore((b).Dtor_core()))))
}
func (_static *CompanionStruct_Default___) DecBound(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(Tok)).Equals(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(451)))) {
		return Companion_PR_.Create_Fail_()
	} else {
		var _source0 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_bid _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _0_bid
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecSel(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_sel m_GoalIr.Sel = _source1.Get_().(PR_Ok).V.(m_GoalIr.Sel)
				_ = _2_sel
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				var _source2 PR = Companion_Default___.DecBCore(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_core m_GoalIr.BCore = _source2.Get_().(PR_Ok).V.(m_GoalIr.BCore)
					_ = _4_core
					var _5_r3 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
					_ = _5_r3
					return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Bound_.Create_Bound_(_0_bid, _2_sel, _4_core), _5_r3)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) EncValidity(v m_GoalIr.Validity) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(460))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncInt((v).Dtor_notBefore()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncInt((v).Dtor_notAfter()), Companion_Default___.EncInt((v).Dtor_maxIdle()))))
}
func (_static *CompanionStruct_Default___) DecValidity(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(Tok)).Equals(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(460)))) {
		return Companion_PR_.Create_Fail_()
	} else {
		var _source0 PR = Companion_Default___.DecInt((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_nb _dafny.Int = _source0.Get_().(PR_Ok).V.(_dafny.Int)
			_ = _0_nb
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecInt(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_na _dafny.Int = _source1.Get_().(PR_Ok).V.(_dafny.Int)
				_ = _2_na
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				var _source2 PR = Companion_Default___.DecInt(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_mi _dafny.Int = _source2.Get_().(PR_Ok).V.(_dafny.Int)
					_ = _4_mi
					var _5_r3 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
					_ = _5_r3
					return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Validity_.Create_Validity_(_0_nb, _2_na, _4_mi), _5_r3)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) EncDeleg(d m_GoalIr.Delegation) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(461))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncInt((d).Dtor_maxDepth()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncBool((d).Dtor_narrowOnly()), Companion_Default___.EncStrs((d).Dtor_mayTouch()))))
}
func (_static *CompanionStruct_Default___) DecDeleg(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(Tok)).Equals(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(461)))) {
		return Companion_PR_.Create_Fail_()
	} else {
		var _source0 PR = Companion_Default___.DecInt((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_md _dafny.Int = _source0.Get_().(PR_Ok).V.(_dafny.Int)
			_ = _0_md
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecBool(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_no bool = _source1.Get_().(PR_Ok).V.(bool)
				_ = _2_no
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				var _source2 PR = Companion_Default___.DecStrs(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_mt _dafny.Sequence = _source2.Get_().(PR_Ok).V.(_dafny.Sequence)
					_ = _4_mt
					var _5_r3 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
					_ = _5_r3
					return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Delegation_.Create_Delegation_(_0_md, _2_no, _4_mt), _5_r3)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) EncHole(h m_GoalIr.Hole) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(470))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr((h).Dtor_hid()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStr((h).Dtor_q()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStrs((h).Dtor_domain()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStrs((h).Dtor_affects()), Companion_Default___.EncBool((h).Dtor_global()))))))
}
func (_static *CompanionStruct_Default___) DecHole(ts _dafny.Sequence) PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(Tok)).Equals(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(470)))) {
		return Companion_PR_.Create_Fail_()
	} else {
		var _source0 PR = Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_hid _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _0_hid
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecStr(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_q _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_q
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				var _source2 PR = Companion_Default___.DecStrs(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_dom _dafny.Sequence = _source2.Get_().(PR_Ok).V.(_dafny.Sequence)
					_ = _4_dom
					var _5_r3 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
					_ = _5_r3
					var _source3 PR = Companion_Default___.DecStrs(_5_r3)
					_ = _source3
					{
						if _source3.Is_Fail() {
							return Companion_PR_.Create_Fail_()
						}
					}
					{
						var _6_aff _dafny.Sequence = _source3.Get_().(PR_Ok).V.(_dafny.Sequence)
						_ = _6_aff
						var _7_r4 _dafny.Sequence = _source3.Get_().(PR_Ok).Rest
						_ = _7_r4
						var _source4 PR = Companion_Default___.DecBool(_7_r4)
						_ = _source4
						{
							if _source4.Is_Fail() {
								return Companion_PR_.Create_Fail_()
							}
						}
						{
							var _8_gl bool = _source4.Get_().(PR_Ok).V.(bool)
							_ = _8_gl
							var _9_r5 _dafny.Sequence = _source4.Get_().(PR_Ok).Rest
							_ = _9_r5
							return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Hole_.Create_Hole_(_0_hid, _2_q, _4_dom, _6_aff, _8_gl), _9_r5)
						}
					}
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) EncStrsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncStr((xs).Select(0).(_dafny.Sequence)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncStrs(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncStrsElems(xs))
}
func (_static *CompanionStruct_Default___) DecStrsElems(ts _dafny.Sequence, n _dafny.Int) PR {
	if (n).Sign() == 0 {
		return Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 PR = Companion_Default___.DecStr(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r
			var _source1 PR = Companion_Default___.DecStrsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				return Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecStrs(ts _dafny.Sequence) PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI())) && ((((ts).Select(0).(Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecStrsElems((ts).Drop(1), ((ts).Select(0).(Tok)).Dtor_i())
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncGrantsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncGrant((xs).Select(0).(m_GoalIr.Grant)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncGrants(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncGrantsElems(xs))
}
func (_static *CompanionStruct_Default___) DecGrantsElems(ts _dafny.Sequence, n _dafny.Int) PR {
	if (n).Sign() == 0 {
		return Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 PR = Companion_Default___.DecGrant(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.Grant = _source0.Get_().(PR_Ok).V.(m_GoalIr.Grant)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r
			var _source1 PR = Companion_Default___.DecGrantsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				return Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecGrants(ts _dafny.Sequence) PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI())) && ((((ts).Select(0).(Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecGrantsElems((ts).Drop(1), ((ts).Select(0).(Tok)).Dtor_i())
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncProhibitsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncProhibit((xs).Select(0).(m_GoalIr.Prohibit)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncProhibits(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncProhibitsElems(xs))
}
func (_static *CompanionStruct_Default___) DecProhibitsElems(ts _dafny.Sequence, n _dafny.Int) PR {
	if (n).Sign() == 0 {
		return Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 PR = Companion_Default___.DecProhibit(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.Prohibit = _source0.Get_().(PR_Ok).V.(m_GoalIr.Prohibit)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r
			var _source1 PR = Companion_Default___.DecProhibitsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				return Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecProhibits(ts _dafny.Sequence) PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI())) && ((((ts).Select(0).(Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecProhibitsElems((ts).Drop(1), ((ts).Select(0).(Tok)).Dtor_i())
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncBoundsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncBound((xs).Select(0).(m_GoalIr.Bound)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncBounds(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncBoundsElems(xs))
}
func (_static *CompanionStruct_Default___) DecBoundsElems(ts _dafny.Sequence, n _dafny.Int) PR {
	if (n).Sign() == 0 {
		return Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 PR = Companion_Default___.DecBound(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.Bound = _source0.Get_().(PR_Ok).V.(m_GoalIr.Bound)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r
			var _source1 PR = Companion_Default___.DecBoundsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				return Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecBounds(ts _dafny.Sequence) PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI())) && ((((ts).Select(0).(Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecBoundsElems((ts).Drop(1), ((ts).Select(0).(Tok)).Dtor_i())
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncCondsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncCond((xs).Select(0).(m_GoalIr.Cond)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncConds(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncCondsElems(xs))
}
func (_static *CompanionStruct_Default___) DecCondsElems(ts _dafny.Sequence, n _dafny.Int) PR {
	if (n).Sign() == 0 {
		return Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 PR = Companion_Default___.DecCondTop(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.Cond = _source0.Get_().(PR_Ok).V.(m_GoalIr.Cond)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r
			var _source1 PR = Companion_Default___.DecCondsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				return Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecConds(ts _dafny.Sequence) PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI())) && ((((ts).Select(0).(Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecCondsElems((ts).Drop(1), ((ts).Select(0).(Tok)).Dtor_i())
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncHolesElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncHole((xs).Select(0).(m_GoalIr.Hole)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncHoles(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncHolesElems(xs))
}
func (_static *CompanionStruct_Default___) DecHolesElems(ts _dafny.Sequence, n _dafny.Int) PR {
	if (n).Sign() == 0 {
		return Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 PR = Companion_Default___.DecHole(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.Hole = _source0.Get_().(PR_Ok).V.(m_GoalIr.Hole)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r
			var _source1 PR = Companion_Default___.DecHolesElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				return Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecHoles(ts _dafny.Sequence) PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(Tok)).Is_TI())) && ((((ts).Select(0).(Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecHolesElems((ts).Drop(1), ((ts).Select(0).(Tok)).Dtor_i())
	} else {
		return Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) EncGoal(g m_GoalIr.Goal) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(480)), Companion_Tok_.Create_TI_((g).Dtor_v()), Companion_Tok_.Create_TS_((g).Dtor_principal()), Companion_Tok_.Create_TS_((g).Dtor_ontDigest()), Companion_Tok_.Create_TS_((g).Dtor_nlDigest())), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStrs((g).Dtor_sources()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncGrants((g).Dtor_grants()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncProhibits((g).Dtor_prohibits()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncBounds((g).Dtor_bounds()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncValidity((g).Dtor_validity()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncDeleg((g).Dtor_deleg()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncConds((g).Dtor_escalateOn()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncStrs((g).Dtor_wildcardAck()), Companion_Default___.EncHoles((g).Dtor_holes()))))))))))
}
func (_static *CompanionStruct_Default___) DecGoal(ts _dafny.Sequence) PR {
	if ((((((_dafny.IntOfUint32((ts).Cardinality())).Cmp(_dafny.IntOfInt64(5)) < 0) || (!((ts).Select(0).(Tok)).Equals(Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(480))))) || (!(((ts).Select(1).(Tok)).Is_TI()))) || (!(((ts).Select(2).(Tok)).Is_TS()))) || (!(((ts).Select(3).(Tok)).Is_TS()))) || (!(((ts).Select(4).(Tok)).Is_TS())) {
		return Companion_PR_.Create_Fail_()
	} else {
		var _source0 PR = Companion_Default___.DecStrs((ts).Drop(5))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_sources _dafny.Sequence = _source0.Get_().(PR_Ok).V.(_dafny.Sequence)
			_ = _0_sources
			var _1_r1 _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_r1
			var _source1 PR = Companion_Default___.DecGrants(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_grants _dafny.Sequence = _source1.Get_().(PR_Ok).V.(_dafny.Sequence)
				_ = _2_grants
				var _3_r2 _dafny.Sequence = _source1.Get_().(PR_Ok).Rest
				_ = _3_r2
				var _source2 PR = Companion_Default___.DecProhibits(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_prohibits _dafny.Sequence = _source2.Get_().(PR_Ok).V.(_dafny.Sequence)
					_ = _4_prohibits
					var _5_r3 _dafny.Sequence = _source2.Get_().(PR_Ok).Rest
					_ = _5_r3
					var _source3 PR = Companion_Default___.DecBounds(_5_r3)
					_ = _source3
					{
						if _source3.Is_Fail() {
							return Companion_PR_.Create_Fail_()
						}
					}
					{
						var _6_bounds _dafny.Sequence = _source3.Get_().(PR_Ok).V.(_dafny.Sequence)
						_ = _6_bounds
						var _7_r4 _dafny.Sequence = _source3.Get_().(PR_Ok).Rest
						_ = _7_r4
						var _source4 PR = Companion_Default___.DecValidity(_7_r4)
						_ = _source4
						{
							if _source4.Is_Fail() {
								return Companion_PR_.Create_Fail_()
							}
						}
						{
							var _8_validity m_GoalIr.Validity = _source4.Get_().(PR_Ok).V.(m_GoalIr.Validity)
							_ = _8_validity
							var _9_r5 _dafny.Sequence = _source4.Get_().(PR_Ok).Rest
							_ = _9_r5
							var _source5 PR = Companion_Default___.DecDeleg(_9_r5)
							_ = _source5
							{
								if _source5.Is_Fail() {
									return Companion_PR_.Create_Fail_()
								}
							}
							{
								var _10_deleg m_GoalIr.Delegation = _source5.Get_().(PR_Ok).V.(m_GoalIr.Delegation)
								_ = _10_deleg
								var _11_r6 _dafny.Sequence = _source5.Get_().(PR_Ok).Rest
								_ = _11_r6
								var _source6 PR = Companion_Default___.DecConds(_11_r6)
								_ = _source6
								{
									if _source6.Is_Fail() {
										return Companion_PR_.Create_Fail_()
									}
								}
								{
									var _12_esc _dafny.Sequence = _source6.Get_().(PR_Ok).V.(_dafny.Sequence)
									_ = _12_esc
									var _13_r7 _dafny.Sequence = _source6.Get_().(PR_Ok).Rest
									_ = _13_r7
									var _source7 PR = Companion_Default___.DecStrs(_13_r7)
									_ = _source7
									{
										if _source7.Is_Fail() {
											return Companion_PR_.Create_Fail_()
										}
									}
									{
										var _14_ack _dafny.Sequence = _source7.Get_().(PR_Ok).V.(_dafny.Sequence)
										_ = _14_ack
										var _15_r8 _dafny.Sequence = _source7.Get_().(PR_Ok).Rest
										_ = _15_r8
										var _source8 PR = Companion_Default___.DecHoles(_15_r8)
										_ = _source8
										{
											if _source8.Is_Fail() {
												return Companion_PR_.Create_Fail_()
											}
										}
										{
											var _16_holes _dafny.Sequence = _source8.Get_().(PR_Ok).V.(_dafny.Sequence)
											_ = _16_holes
											var _17_r9 _dafny.Sequence = _source8.Get_().(PR_Ok).Rest
											_ = _17_r9
											return Companion_PR_.Create_Ok_(m_GoalIr.Companion_Goal_.Create_Goal_(((ts).Select(1).(Tok)).Dtor_i(), ((ts).Select(2).(Tok)).Dtor_s(), ((ts).Select(3).(Tok)).Dtor_s(), ((ts).Select(4).(Tok)).Dtor_s(), _0_sources, _2_grants, _4_prohibits, _6_bounds, _8_validity, _10_deleg, _12_esc, _14_ack, _16_holes), _17_r9)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) Render(g m_GoalIr.Goal) _dafny.Sequence {
	return Companion_Default___.EncGoal(g)
}
func (_static *CompanionStruct_Default___) Parse(ts _dafny.Sequence) m_GoalIr.Option {
	var _source0 PR = Companion_Default___.DecGoal(ts)
	_ = _source0
	{
		if _source0.Is_Ok() {
			var _0_g m_GoalIr.Goal = _source0.Get_().(PR_Ok).V.(m_GoalIr.Goal)
			_ = _0_g
			var _1_rest _dafny.Sequence = _source0.Get_().(PR_Ok).Rest
			_ = _1_rest
			if (_dafny.IntOfUint32((_1_rest).Cardinality())).Sign() == 0 {
				return m_GoalIr.Companion_Option_.Create_Some_(_0_g)
			} else {
				return m_GoalIr.Companion_Option_.Create_None_()
			}
		}
	}
	{
		return m_GoalIr.Companion_Option_.Create_None_()
	}
}

// End of class Default__

// Definition of datatype Tok
type Tok struct {
	Data_Tok_
}

func (_this Tok) Get_() Data_Tok_ {
	return _this.Data_Tok_
}

type Data_Tok_ interface {
	isTok()
}

type CompanionStruct_Tok_ struct {
}

var Companion_Tok_ = CompanionStruct_Tok_{}

type Tok_TKw struct {
	K _dafny.Int
}

func (Tok_TKw) isTok() {}

func (CompanionStruct_Tok_) Create_TKw_(K _dafny.Int) Tok {
	return Tok{Tok_TKw{K}}
}

func (_this Tok) Is_TKw() bool {
	_, ok := _this.Get_().(Tok_TKw)
	return ok
}

type Tok_TI struct {
	I _dafny.Int
}

func (Tok_TI) isTok() {}

func (CompanionStruct_Tok_) Create_TI_(I _dafny.Int) Tok {
	return Tok{Tok_TI{I}}
}

func (_this Tok) Is_TI() bool {
	_, ok := _this.Get_().(Tok_TI)
	return ok
}

type Tok_TS struct {
	S _dafny.Sequence
}

func (Tok_TS) isTok() {}

func (CompanionStruct_Tok_) Create_TS_(S _dafny.Sequence) Tok {
	return Tok{Tok_TS{S}}
}

func (_this Tok) Is_TS() bool {
	_, ok := _this.Get_().(Tok_TS)
	return ok
}

func (CompanionStruct_Tok_) Default() Tok {
	return Companion_Tok_.Create_TKw_(_dafny.Zero)
}

func (_this Tok) Dtor_k() _dafny.Int {
	return _this.Get_().(Tok_TKw).K
}

func (_this Tok) Dtor_i() _dafny.Int {
	return _this.Get_().(Tok_TI).I
}

func (_this Tok) Dtor_s() _dafny.Sequence {
	return _this.Get_().(Tok_TS).S
}

func (_this Tok) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Tok_TKw:
		{
			return "GoalRender.Tok.TKw" + "(" + _dafny.String(data.K) + ")"
		}
	case Tok_TI:
		{
			return "GoalRender.Tok.TI" + "(" + _dafny.String(data.I) + ")"
		}
	case Tok_TS:
		{
			return "GoalRender.Tok.TS" + "(" + data.S.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Tok) Equals(other Tok) bool {
	switch data1 := _this.Get_().(type) {
	case Tok_TKw:
		{
			data2, ok := other.Get_().(Tok_TKw)
			return ok && data1.K.Cmp(data2.K) == 0
		}
	case Tok_TI:
		{
			data2, ok := other.Get_().(Tok_TI)
			return ok && data1.I.Cmp(data2.I) == 0
		}
	case Tok_TS:
		{
			data2, ok := other.Get_().(Tok_TS)
			return ok && data1.S.Equals(data2.S)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Tok) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Tok)
	return ok && _this.Equals(typed)
}

func Type_Tok_() _dafny.TypeDescriptor {
	return type_Tok_{}
}

type type_Tok_ struct {
}

func (_this type_Tok_) Default() interface{} {
	return Companion_Tok_.Default()
}

func (_this type_Tok_) String() string {
	return "GoalRender.Tok"
}
func (_this Tok) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Tok{}

// End of datatype Tok

// Definition of datatype PR
type PR struct {
	Data_PR_
}

func (_this PR) Get_() Data_PR_ {
	return _this.Data_PR_
}

type Data_PR_ interface {
	isPR()
}

type CompanionStruct_PR_ struct {
}

var Companion_PR_ = CompanionStruct_PR_{}

type PR_Fail struct {
}

func (PR_Fail) isPR() {}

func (CompanionStruct_PR_) Create_Fail_() PR {
	return PR{PR_Fail{}}
}

func (_this PR) Is_Fail() bool {
	_, ok := _this.Get_().(PR_Fail)
	return ok
}

type PR_Ok struct {
	V    interface{}
	Rest _dafny.Sequence
}

func (PR_Ok) isPR() {}

func (CompanionStruct_PR_) Create_Ok_(V interface{}, Rest _dafny.Sequence) PR {
	return PR{PR_Ok{V, Rest}}
}

func (_this PR) Is_Ok() bool {
	_, ok := _this.Get_().(PR_Ok)
	return ok
}

func (CompanionStruct_PR_) Default() PR {
	return Companion_PR_.Create_Fail_()
}

func (_this PR) Dtor_v() interface{} {
	return _this.Get_().(PR_Ok).V
}

func (_this PR) Dtor_rest() _dafny.Sequence {
	return _this.Get_().(PR_Ok).Rest
}

func (_this PR) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case PR_Fail:
		{
			return "GoalRender.PR.Fail"
		}
	case PR_Ok:
		{
			return "GoalRender.PR.Ok" + "(" + _dafny.String(data.V) + ", " + _dafny.String(data.Rest) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this PR) Equals(other PR) bool {
	switch data1 := _this.Get_().(type) {
	case PR_Fail:
		{
			_, ok := other.Get_().(PR_Fail)
			return ok
		}
	case PR_Ok:
		{
			data2, ok := other.Get_().(PR_Ok)
			return ok && _dafny.AreEqual(data1.V, data2.V) && data1.Rest.Equals(data2.Rest)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this PR) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(PR)
	return ok && _this.Equals(typed)
}

func Type_PR_() _dafny.TypeDescriptor {
	return type_PR_{}
}

type type_PR_ struct {
}

func (_this type_PR_) Default() interface{} {
	return Companion_PR_.Default()
}

func (_this type_PR_) String() string {
	return "GoalRender.PR"
}
func (_this PR) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = PR{}

// End of datatype PR
