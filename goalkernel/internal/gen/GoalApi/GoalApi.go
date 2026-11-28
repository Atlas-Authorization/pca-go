// Package GoalApi
// Dafny module GoalApi compiled into Go

package GoalApi

import (
	m_GoalCompile "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/GoalCompile"
	m_GoalIr "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/GoalIr"
	m_GoalRender "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/GoalRender"
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
var _ m_GoalRender.Dummy__

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
	return "GoalApi.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) DecParamDecl(ts _dafny.Sequence) m_GoalRender.PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(m_GoalRender.Tok)).Equals(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(500)))) {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	} else {
		var _source0 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_p _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
			_ = _0_p
			var _1_r1 _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r1
			var _source1 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecTy(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_ty m_GoalIr.Ty = _source1.Get_().(m_GoalRender.PR_Ok).V.(m_GoalIr.Ty)
				_ = _2_ty
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				return m_GoalRender.Companion_PR_.Create_Ok_(m_GoalIr.Companion_ParamDecl_.Create_ParamDecl_(_0_p, _2_ty), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecParamDeclsElems(ts _dafny.Sequence, n _dafny.Int) m_GoalRender.PR {
	if (n).Sign() == 0 {
		return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 m_GoalRender.PR = Companion_Default___.DecParamDecl(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.ParamDecl = _source0.Get_().(m_GoalRender.PR_Ok).V.(m_GoalIr.ParamDecl)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r
			var _source1 m_GoalRender.PR = Companion_Default___.DecParamDeclsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecParamDecls(ts _dafny.Sequence) m_GoalRender.PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(m_GoalRender.Tok)).Is_TI())) && ((((ts).Select(0).(m_GoalRender.Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecParamDeclsElems((ts).Drop(1), ((ts).Select(0).(m_GoalRender.Tok)).Dtor_i())
	} else {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) DecVerbDecl(ts _dafny.Sequence) m_GoalRender.PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(m_GoalRender.Tok)).Equals(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(501)))) {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	} else {
		var _source0 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_v _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
			_ = _0_v
			var _1_r1 _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r1
			var _source1 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_c _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
				_ = _2_c
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				var _source2 m_GoalRender.PR = Companion_Default___.DecParamDecls(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return m_GoalRender.Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_ps _dafny.Sequence = _source2.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
					_ = _4_ps
					var _5_r3 _dafny.Sequence = _source2.Get_().(m_GoalRender.PR_Ok).Rest
					_ = _5_r3
					return m_GoalRender.Companion_PR_.Create_Ok_(m_GoalIr.Companion_VerbDecl_.Create_VerbDecl_(_0_v, _2_c, _4_ps), _5_r3)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecRelDecl(ts _dafny.Sequence) m_GoalRender.PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(m_GoalRender.Tok)).Equals(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(502)))) {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	} else {
		var _source0 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_rel _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
			_ = _0_rel
			var _1_r1 _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r1
			var _source1 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_an _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
				_ = _2_an
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				var _source2 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStrs(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return m_GoalRender.Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_ms _dafny.Sequence = _source2.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
					_ = _4_ms
					var _5_r3 _dafny.Sequence = _source2.Get_().(m_GoalRender.PR_Ok).Rest
					_ = _5_r3
					return m_GoalRender.Companion_PR_.Create_Ok_(m_GoalIr.Companion_RelDecl_.Create_RelDecl_(_0_rel, _2_an, _4_ms), _5_r3)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecVerbDeclsElems(ts _dafny.Sequence, n _dafny.Int) m_GoalRender.PR {
	if (n).Sign() == 0 {
		return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 m_GoalRender.PR = Companion_Default___.DecVerbDecl(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.VerbDecl = _source0.Get_().(m_GoalRender.PR_Ok).V.(m_GoalIr.VerbDecl)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r
			var _source1 m_GoalRender.PR = Companion_Default___.DecVerbDeclsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecVerbDecls(ts _dafny.Sequence) m_GoalRender.PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(m_GoalRender.Tok)).Is_TI())) && ((((ts).Select(0).(m_GoalRender.Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecVerbDeclsElems((ts).Drop(1), ((ts).Select(0).(m_GoalRender.Tok)).Dtor_i())
	} else {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) DecRelDeclsElems(ts _dafny.Sequence, n _dafny.Int) m_GoalRender.PR {
	if (n).Sign() == 0 {
		return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 m_GoalRender.PR = Companion_Default___.DecRelDecl(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.RelDecl = _source0.Get_().(m_GoalRender.PR_Ok).V.(m_GoalIr.RelDecl)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r
			var _source1 m_GoalRender.PR = Companion_Default___.DecRelDeclsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecRelDecls(ts _dafny.Sequence) m_GoalRender.PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(m_GoalRender.Tok)).Is_TI())) && ((((ts).Select(0).(m_GoalRender.Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecRelDeclsElems((ts).Drop(1), ((ts).Select(0).(m_GoalRender.Tok)).Dtor_i())
	} else {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) DecOntology(ts _dafny.Sequence) m_GoalRender.PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(m_GoalRender.Tok)).Equals(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(510)))) {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	} else {
		var _source0 m_GoalRender.PR = Companion_Default___.DecVerbDecls((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_vs _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
			_ = _0_vs
			var _1_r1 _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r1
			var _source1 m_GoalRender.PR = Companion_Default___.DecRelDecls(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_rs _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
				_ = _2_rs
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				return m_GoalRender.Companion_PR_.Create_Ok_(m_GoalIr.Companion_Ontology_.Create_Ontology_(_0_vs, _2_rs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecParamEntries(ts _dafny.Sequence, n _dafny.Int) m_GoalRender.PR {
	if (n).Sign() == 0 {
		return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.NewMapBuilder().ToMap(), ts)
	} else if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(m_GoalRender.Tok)).Equals(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(520)))) {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	} else {
		var _source0 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_k _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
			_ = _0_k
			var _1_r1 _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r1
			var _source1 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecV(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_v m_GoalIr.V = _source1.Get_().(m_GoalRender.PR_Ok).V.(m_GoalIr.V)
				_ = _2_v
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				var _source2 m_GoalRender.PR = Companion_Default___.DecParamEntries(_3_r2, (n).Minus(_dafny.One))
				_ = _source2
				{
					if _source2.Is_Fail() {
						return m_GoalRender.Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_m _dafny.Map = _source2.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Map)
					_ = _4_m
					var _5_r3 _dafny.Sequence = _source2.Get_().(m_GoalRender.PR_Ok).Rest
					_ = _5_r3
					return m_GoalRender.Companion_PR_.Create_Ok_((_4_m).Update(_0_k, _2_v), _5_r3)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecParams(ts _dafny.Sequence) m_GoalRender.PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(m_GoalRender.Tok)).Is_TI())) && ((((ts).Select(0).(m_GoalRender.Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecParamEntries((ts).Drop(1), ((ts).Select(0).(m_GoalRender.Tok)).Dtor_i())
	} else {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) DecAct(ts _dafny.Sequence) m_GoalRender.PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(m_GoalRender.Tok)).Equals(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(530)))) {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	} else {
		var _source0 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_verb _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
			_ = _0_verb
			var _1_r1 _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r1
			var _source1 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_res _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
				_ = _2_res
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				var _source2 m_GoalRender.PR = Companion_Default___.DecParams(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return m_GoalRender.Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_ps _dafny.Map = _source2.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Map)
					_ = _4_ps
					var _5_r3 _dafny.Sequence = _source2.Get_().(m_GoalRender.PR_Ok).Rest
					_ = _5_r3
					var _source3 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecInt(_5_r3)
					_ = _source3
					{
						if _source3.Is_Fail() {
							return m_GoalRender.Companion_PR_.Create_Fail_()
						}
					}
					{
						var _6_t _dafny.Int = _source3.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Int)
						_ = _6_t
						var _7_r4 _dafny.Sequence = _source3.Get_().(m_GoalRender.PR_Ok).Rest
						_ = _7_r4
						var _source4 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr(_7_r4)
						_ = _source4
						{
							if _source4.Is_Fail() {
								return m_GoalRender.Companion_PR_.Create_Fail_()
							}
						}
						{
							var _8_sess _dafny.Sequence = _source4.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
							_ = _8_sess
							var _9_r5 _dafny.Sequence = _source4.Get_().(m_GoalRender.PR_Ok).Rest
							_ = _9_r5
							var _source5 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr(_9_r5)
							_ = _source5
							{
								if _source5.Is_Fail() {
									return m_GoalRender.Companion_PR_.Create_Fail_()
								}
							}
							{
								var _10_prin _dafny.Sequence = _source5.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
								_ = _10_prin
								var _11_r6 _dafny.Sequence = _source5.Get_().(m_GoalRender.PR_Ok).Rest
								_ = _11_r6
								var _source6 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr(_11_r6)
								_ = _source6
								{
									if _source6.Is_Fail() {
										return m_GoalRender.Companion_PR_.Create_Fail_()
									}
								}
								{
									var _12_org _dafny.Sequence = _source6.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
									_ = _12_org
									var _13_r7 _dafny.Sequence = _source6.Get_().(m_GoalRender.PR_Ok).Rest
									_ = _13_r7
									var _source7 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr(_13_r7)
									_ = _source7
									{
										if _source7.Is_Fail() {
											return m_GoalRender.Companion_PR_.Create_Fail_()
										}
									}
									{
										var _14_agent _dafny.Sequence = _source7.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
										_ = _14_agent
										var _15_r8 _dafny.Sequence = _source7.Get_().(m_GoalRender.PR_Ok).Rest
										_ = _15_r8
										var _source8 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecInt(_15_r8)
										_ = _source8
										{
											if _source8.Is_Fail() {
												return m_GoalRender.Companion_PR_.Create_Fail_()
											}
										}
										{
											var _16_depth _dafny.Int = _source8.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Int)
											_ = _16_depth
											var _17_r9 _dafny.Sequence = _source8.Get_().(m_GoalRender.PR_Ok).Rest
											_ = _17_r9
											return m_GoalRender.Companion_PR_.Create_Ok_(m_GoalIr.Companion_Act_.Create_Act_(_0_verb, _2_res, _4_ps, _6_t, _8_sess, _10_prin, _12_org, _14_agent, _16_depth), _17_r9)
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
func (_static *CompanionStruct_Default___) DecAdm(ts _dafny.Sequence) m_GoalRender.PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(m_GoalRender.Tok)).Equals(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(531)))) {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	} else {
		var _source0 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_gid _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
			_ = _0_gid
			var _1_r1 _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r1
			var _source1 m_GoalRender.PR = Companion_Default___.DecAct(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_a m_GoalIr.Act = _source1.Get_().(m_GoalRender.PR_Ok).V.(m_GoalIr.Act)
				_ = _2_a
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				return m_GoalRender.Companion_PR_.Create_Ok_(m_GoalIr.Companion_Adm_.Create_Adm_(_0_gid, _2_a), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecAdmsElems(ts _dafny.Sequence, n _dafny.Int) m_GoalRender.PR {
	if (n).Sign() == 0 {
		return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.SeqOf(), ts)
	} else {
		var _source0 m_GoalRender.PR = Companion_Default___.DecAdm(ts)
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_x m_GoalIr.Adm = _source0.Get_().(m_GoalRender.PR_Ok).V.(m_GoalIr.Adm)
			_ = _0_x
			var _1_r _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r
			var _source1 m_GoalRender.PR = Companion_Default___.DecAdmsElems(_1_r, (n).Minus(_dafny.One))
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_xs _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
				_ = _2_xs
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_0_x), _2_xs), _3_r2)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecAdms(ts _dafny.Sequence) m_GoalRender.PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(m_GoalRender.Tok)).Is_TI())) && ((((ts).Select(0).(m_GoalRender.Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecAdmsElems((ts).Drop(1), ((ts).Select(0).(m_GoalRender.Tok)).Dtor_i())
	} else {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) DecAggEntries(ts _dafny.Sequence, n _dafny.Int) m_GoalRender.PR {
	if (n).Sign() == 0 {
		return m_GoalRender.Companion_PR_.Create_Ok_(_dafny.NewMapBuilder().ToMap(), ts)
	} else if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(m_GoalRender.Tok)).Equals(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(540)))) {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	} else {
		var _source0 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecStr((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_k _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
			_ = _0_k
			var _1_r1 _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r1
			var _source1 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecQ(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_q m_GoalIr.Q = _source1.Get_().(m_GoalRender.PR_Ok).V.(m_GoalIr.Q)
				_ = _2_q
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				var _source2 m_GoalRender.PR = Companion_Default___.DecAggEntries(_3_r2, (n).Minus(_dafny.One))
				_ = _source2
				{
					if _source2.Is_Fail() {
						return m_GoalRender.Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_m _dafny.Map = _source2.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Map)
					_ = _4_m
					var _5_r3 _dafny.Sequence = _source2.Get_().(m_GoalRender.PR_Ok).Rest
					_ = _5_r3
					return m_GoalRender.Companion_PR_.Create_Ok_((_4_m).Update(_0_k, _2_q), _5_r3)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) DecAggs(ts _dafny.Sequence) m_GoalRender.PR {
	if (((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 1) && (((ts).Select(0).(m_GoalRender.Tok)).Is_TI())) && ((((ts).Select(0).(m_GoalRender.Tok)).Dtor_i()).Sign() != -1) {
		return Companion_Default___.DecAggEntries((ts).Drop(1), ((ts).Select(0).(m_GoalRender.Tok)).Dtor_i())
	} else {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	}
}
func (_static *CompanionStruct_Default___) DecHist(ts _dafny.Sequence) m_GoalRender.PR {
	if ((_dafny.IntOfUint32((ts).Cardinality())).Sign() == 0) || (!((ts).Select(0).(m_GoalRender.Tok)).Equals(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(541)))) {
		return m_GoalRender.Companion_PR_.Create_Fail_()
	} else {
		var _source0 m_GoalRender.PR = Companion_Default___.DecAdms((ts).Drop(1))
		_ = _source0
		{
			if _source0.Is_Fail() {
				return m_GoalRender.Companion_PR_.Create_Fail_()
			}
		}
		{
			var _0_adms _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Sequence)
			_ = _0_adms
			var _1_r1 _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_r1
			var _source1 m_GoalRender.PR = m_GoalRender.Companion_Default___.DecInt(_1_r1)
			_ = _source1
			{
				if _source1.Is_Fail() {
					return m_GoalRender.Companion_PR_.Create_Fail_()
				}
			}
			{
				var _2_last _dafny.Int = _source1.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Int)
				_ = _2_last
				var _3_r2 _dafny.Sequence = _source1.Get_().(m_GoalRender.PR_Ok).Rest
				_ = _3_r2
				var _source2 m_GoalRender.PR = Companion_Default___.DecAggs(_3_r2)
				_ = _source2
				{
					if _source2.Is_Fail() {
						return m_GoalRender.Companion_PR_.Create_Fail_()
					}
				}
				{
					var _4_aggs _dafny.Map = _source2.Get_().(m_GoalRender.PR_Ok).V.(_dafny.Map)
					_ = _4_aggs
					var _5_r3 _dafny.Sequence = _source2.Get_().(m_GoalRender.PR_Ok).Rest
					_ = _5_r3
					return m_GoalRender.Companion_PR_.Create_Ok_(m_GoalIr.Companion_Hist_.Create_Hist_(_0_adms, _2_last, _4_aggs), _5_r3)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) Whole(r m_GoalRender.PR) m_GoalIr.Option {
	var _source0 m_GoalRender.PR = r
	_ = _source0
	{
		if _source0.Is_Ok() {
			var _0_v interface{} = _source0.Get_().(m_GoalRender.PR_Ok).V
			_ = _0_v
			var _1_rest _dafny.Sequence = _source0.Get_().(m_GoalRender.PR_Ok).Rest
			_ = _1_rest
			if (_dafny.IntOfUint32((_1_rest).Cardinality())).Sign() == 0 {
				return m_GoalIr.Companion_Option_.Create_Some_(_0_v)
			} else {
				return m_GoalIr.Companion_Option_.Create_None_()
			}
		}
	}
	{
		return m_GoalIr.Companion_Option_.Create_None_()
	}
}
func (_static *CompanionStruct_Default___) EncResPat(p m_GoalIr.ResPat) _dafny.Sequence {
	var _source0 m_GoalIr.ResPat = p
	_ = _source0
	{
		if _source0.Is_PStar() {
			return _dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(630)))
		}
	}
	{
		var _0_ids _dafny.Sequence = _source0.Get_().(m_GoalIr.ResPat_PSet).Ids
		_ = _0_ids
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(631))), m_GoalRender.Companion_Default___.EncStrs(_0_ids))
	}
}
func (_static *CompanionStruct_Default___) EncNC(c m_GoalCompile.NC) _dafny.Sequence {
	var _source0 m_GoalCompile.NC = c
	_ = _source0
	{
		if _source0.Is_NTrue() {
			return _dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(600)))
		}
	}
	{
		if _source0.Is_NFalse() {
			return _dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(601)))
		}
	}
	{
		if _source0.Is_NAtom() {
			var _0_op m_GoalIr.Op = _source0.Get_().(m_GoalCompile.NC_NAtom).Op
			_ = _0_op
			var _1_l m_GoalIr.Term = _source0.Get_().(m_GoalCompile.NC_NAtom).L
			_ = _1_l
			var _2_r m_GoalIr.Term = _source0.Get_().(m_GoalCompile.NC_NAtom).R
			_ = _2_r
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(602))), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncOp(_0_op), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncTerm(_1_l), m_GoalRender.Companion_Default___.EncTerm(_2_r))))
		}
	}
	{
		if _source0.Is_NAnd() {
			var _3_x m_GoalCompile.NC = _source0.Get_().(m_GoalCompile.NC_NAnd).A
			_ = _3_x
			var _4_y m_GoalCompile.NC = _source0.Get_().(m_GoalCompile.NC_NAnd).B
			_ = _4_y
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(603))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncNC(_3_x), Companion_Default___.EncNC(_4_y)))
		}
	}
	{
		var _5_x m_GoalCompile.NC = _source0.Get_().(m_GoalCompile.NC_NOr).A
		_ = _5_x
		var _6_y m_GoalCompile.NC = _source0.Get_().(m_GoalCompile.NC_NOr).B
		_ = _6_y
		return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(604))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncNC(_5_x), Companion_Default___.EncNC(_6_y)))
	}
}
func (_static *CompanionStruct_Default___) EncLPred(p m_GoalCompile.LPred) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(620))), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncStr((p).Dtor_gid()), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncStr((p).Dtor_verb()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncResPat((p).Dtor_res()), Companion_Default___.EncNC((p).Dtor_cond())))))
}
func (_static *CompanionStruct_Default___) EncLProh(p m_GoalCompile.LProh) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(640))), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncStr((p).Dtor_pid()), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncStrs((p).Dtor_verbs()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncResPat((p).Dtor_res()), Companion_Default___.EncNC((p).Dtor_cond())))))
}
func (_static *CompanionStruct_Default___) EncLCeil(c m_GoalCompile.LCeil) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(610))), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncStr((c).Dtor_bid()), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncStrs(((c).Dtor_sel()).Dtor_gids()), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncStrs(((c).Dtor_sel()).Dtor_verbs()), m_GoalRender.Companion_Default___.EncBCore((c).Dtor_core())))))
}
func (_static *CompanionStruct_Default___) EncLPredsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncLPred((xs).Select(0).(m_GoalCompile.LPred)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncLPreds(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncLPredsElems(xs))
}
func (_static *CompanionStruct_Default___) EncLProhsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncLProh((xs).Select(0).(m_GoalCompile.LProh)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncLProhs(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncLProhsElems(xs))
}
func (_static *CompanionStruct_Default___) EncLCeilsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncLCeil((xs).Select(0).(m_GoalCompile.LCeil)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncLCeils(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncLCeilsElems(xs))
}
func (_static *CompanionStruct_Default___) EncNCsElems(xs _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((xs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, Companion_Default___.EncNC((xs).Select(0).(m_GoalCompile.NC)))
		var _in0 _dafny.Sequence = (xs).Drop(1)
		_ = _in0
		xs = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) EncNCs(xs _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.IntOfUint32((xs).Cardinality()))), Companion_Default___.EncNCsElems(xs))
}
func (_static *CompanionStruct_Default___) EncPol(p m_GoalCompile.Pol) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TKw_(_dafny.IntOfInt64(650))), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncLPreds((p).Dtor_preds()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncLProhs((p).Dtor_prohs()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncLCeils((p).Dtor_ceils()), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.EncNCs((p).Dtor_escs()), _dafny.Companion_Sequence_.Concatenate(m_GoalRender.Companion_Default___.EncValidity((p).Dtor_validity()), m_GoalRender.Companion_Default___.EncDeleg((p).Dtor_deleg())))))))
}
func (_static *CompanionStruct_Default___) MkKw(k _dafny.Int) m_GoalRender.Tok {
	return m_GoalRender.Companion_Tok_.Create_TKw_(k)
}
func (_static *CompanionStruct_Default___) MkI(i _dafny.Int) m_GoalRender.Tok {
	return m_GoalRender.Companion_Tok_.Create_TI_(i)
}
func (_static *CompanionStruct_Default___) MkS(s _dafny.Sequence) m_GoalRender.Tok {
	return m_GoalRender.Companion_Tok_.Create_TS_(s)
}
func (_static *CompanionStruct_Default___) TokKind(t m_GoalRender.Tok) _dafny.Int {
	var _source0 m_GoalRender.Tok = t
	_ = _source0
	{
		if _source0.Is_TKw() {
			return _dafny.Zero
		}
	}
	{
		if _source0.Is_TI() {
			return _dafny.One
		}
	}
	{
		return _dafny.IntOfInt64(2)
	}
}
func (_static *CompanionStruct_Default___) TokKw(t m_GoalRender.Tok) _dafny.Int {
	var _source0 m_GoalRender.Tok = t
	_ = _source0
	{
		if _source0.Is_TKw() {
			var _0_k _dafny.Int = _source0.Get_().(m_GoalRender.Tok_TKw).K
			_ = _0_k
			return _0_k
		}
	}
	{
		return _dafny.Zero
	}
}
func (_static *CompanionStruct_Default___) TokInt(t m_GoalRender.Tok) _dafny.Int {
	var _source0 m_GoalRender.Tok = t
	_ = _source0
	{
		if _source0.Is_TI() {
			var _0_i _dafny.Int = _source0.Get_().(m_GoalRender.Tok_TI).I
			_ = _0_i
			return _0_i
		}
	}
	{
		return _dafny.Zero
	}
}
func (_static *CompanionStruct_Default___) TokStr(t m_GoalRender.Tok) _dafny.Sequence {
	var _source0 m_GoalRender.Tok = t
	_ = _source0
	{
		if _source0.Is_TS() {
			var _0_s _dafny.Sequence = _source0.Get_().(m_GoalRender.Tok_TS).S
			_ = _0_s
			return _0_s
		}
	}
	{
		return _dafny.UnicodeSeqOfUtf8Bytes("")
	}
}
func (_static *CompanionStruct_Default___) Bad() _dafny.Sequence {
	return _dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.IntOfInt64(9)))
}
func (_static *CompanionStruct_Default___) ParseG(ts _dafny.Sequence) m_GoalIr.Option {
	return m_GoalRender.Companion_Default___.Parse(ts)
}
func (_static *CompanionStruct_Default___) TypecheckT(gt _dafny.Sequence, ot _dafny.Sequence) _dafny.Sequence {
	var _source0 _dafny.Tuple = _dafny.TupleOf(Companion_Default___.ParseG(gt), Companion_Default___.Whole(Companion_Default___.DecOntology(ot)))
	_ = _source0
	{
		var _00 m_GoalIr.Option = (*(_source0).IndexInt(0)).(m_GoalIr.Option)
		_ = _00
		if _00.Is_Some() {
			var _0_g m_GoalIr.Goal = _00.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Goal)
			_ = _0_g
			var _10 m_GoalIr.Option = (*(_source0).IndexInt(1)).(m_GoalIr.Option)
			_ = _10
			if _10.Is_Some() {
				var _1_o m_GoalIr.Ontology = _10.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Ontology)
				_ = _1_o
				var _2_rs _dafny.Sequence = m_GoalCompile.Companion_Default___.TypeReasons(_1_o, _0_g)
				_ = _2_rs
				if (_dafny.IntOfUint32((_2_rs).Cardinality())).Sign() == 0 {
					return _dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.Zero))
				} else {
					return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.One)), m_GoalRender.Companion_Default___.EncStrs(_2_rs))
				}
			}
		}
	}
	{
		return Companion_Default___.Bad()
	}
}
func (_static *CompanionStruct_Default___) CompileT(gt _dafny.Sequence, ot _dafny.Sequence) _dafny.Sequence {
	var _source0 _dafny.Tuple = _dafny.TupleOf(Companion_Default___.ParseG(gt), Companion_Default___.Whole(Companion_Default___.DecOntology(ot)))
	_ = _source0
	{
		var _00 m_GoalIr.Option = (*(_source0).IndexInt(0)).(m_GoalIr.Option)
		_ = _00
		if _00.Is_Some() {
			var _0_g m_GoalIr.Goal = _00.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Goal)
			_ = _0_g
			var _10 m_GoalIr.Option = (*(_source0).IndexInt(1)).(m_GoalIr.Option)
			_ = _10
			if _10.Is_Some() {
				var _1_o m_GoalIr.Ontology = _10.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Ontology)
				_ = _1_o
				var _source1 m_GoalCompile.CResult = m_GoalCompile.Companion_Default___.Compile(_1_o, _0_g)
				_ = _source1
				{
					if _source1.Is_Compiled() {
						var _2_p m_GoalCompile.Pol = _source1.Get_().(m_GoalCompile.CResult_Compiled).P
						_ = _2_p
						return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.Zero)), Companion_Default___.EncPol(_2_p))
					}
				}
				{
					var _3_rs _dafny.Sequence = _source1.Get_().(m_GoalCompile.CResult_CEscalate).Reasons
					_ = _3_rs
					return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.One)), m_GoalRender.Companion_Default___.EncStrs(_3_rs))
				}
			}
		}
	}
	{
		return Companion_Default___.Bad()
	}
}
func (_static *CompanionStruct_Default___) DecideGoalT(gt _dafny.Sequence, ot _dafny.Sequence, at _dafny.Sequence, ht _dafny.Sequence) _dafny.Sequence {
	var _source0 _dafny.Tuple = _dafny.TupleOf(Companion_Default___.ParseG(gt), Companion_Default___.Whole(Companion_Default___.DecOntology(ot)), Companion_Default___.Whole(Companion_Default___.DecAct(at)), Companion_Default___.Whole(Companion_Default___.DecHist(ht)))
	_ = _source0
	{
		var _00 m_GoalIr.Option = (*(_source0).IndexInt(0)).(m_GoalIr.Option)
		_ = _00
		if _00.Is_Some() {
			var _0_g m_GoalIr.Goal = _00.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Goal)
			_ = _0_g
			var _10 m_GoalIr.Option = (*(_source0).IndexInt(1)).(m_GoalIr.Option)
			_ = _10
			if _10.Is_Some() {
				var _1_o m_GoalIr.Ontology = _10.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Ontology)
				_ = _1_o
				var _20 m_GoalIr.Option = (*(_source0).IndexInt(2)).(m_GoalIr.Option)
				_ = _20
				if _20.Is_Some() {
					var _2_a m_GoalIr.Act = _20.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Act)
					_ = _2_a
					var _30 m_GoalIr.Option = (*(_source0).IndexInt(3)).(m_GoalIr.Option)
					_ = _30
					if _30.Is_Some() {
						var _3_h m_GoalIr.Hist = _30.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Hist)
						_ = _3_h
						return _dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.Zero), m_GoalRender.Companion_Tok_.Create_TI_(m_GoalIr.Companion_Default___.DG(_1_o, _0_g, _2_a, _3_h)))
					}
				}
			}
		}
	}
	{
		return Companion_Default___.Bad()
	}
}
func (_static *CompanionStruct_Default___) DecidePolicyT(gt _dafny.Sequence, ot _dafny.Sequence, at _dafny.Sequence, ht _dafny.Sequence) _dafny.Sequence {
	var _source0 _dafny.Tuple = _dafny.TupleOf(Companion_Default___.ParseG(gt), Companion_Default___.Whole(Companion_Default___.DecOntology(ot)), Companion_Default___.Whole(Companion_Default___.DecAct(at)), Companion_Default___.Whole(Companion_Default___.DecHist(ht)))
	_ = _source0
	{
		var _00 m_GoalIr.Option = (*(_source0).IndexInt(0)).(m_GoalIr.Option)
		_ = _00
		if _00.Is_Some() {
			var _0_g m_GoalIr.Goal = _00.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Goal)
			_ = _0_g
			var _10 m_GoalIr.Option = (*(_source0).IndexInt(1)).(m_GoalIr.Option)
			_ = _10
			if _10.Is_Some() {
				var _1_o m_GoalIr.Ontology = _10.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Ontology)
				_ = _1_o
				var _20 m_GoalIr.Option = (*(_source0).IndexInt(2)).(m_GoalIr.Option)
				_ = _20
				if _20.Is_Some() {
					var _2_a m_GoalIr.Act = _20.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Act)
					_ = _2_a
					var _30 m_GoalIr.Option = (*(_source0).IndexInt(3)).(m_GoalIr.Option)
					_ = _30
					if _30.Is_Some() {
						var _3_h m_GoalIr.Hist = _30.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Hist)
						_ = _3_h
						var _source1 m_GoalCompile.CResult = m_GoalCompile.Companion_Default___.Compile(_1_o, _0_g)
						_ = _source1
						{
							if _source1.Is_CEscalate() {
								var _4_rs _dafny.Sequence = _source1.Get_().(m_GoalCompile.CResult_CEscalate).Reasons
								_ = _4_rs
								return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.One)), m_GoalRender.Companion_Default___.EncStrs(_4_rs))
							}
						}
						{
							var _5_p m_GoalCompile.Pol = _source1.Get_().(m_GoalCompile.CResult_Compiled).P
							_ = _5_p
							var _6_r _dafny.Tuple = m_GoalWitness.Companion_Default___.DecideW(_5_p, _2_a, _3_h)
							_ = _6_r
							return _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.Zero), m_GoalRender.Companion_Tok_.Create_TI_((*(_6_r).IndexInt(0)).(_dafny.Int)), m_GoalRender.Companion_Tok_.Create_TS_(((*(_6_r).IndexInt(1)).(m_GoalWitness.Wit)).Dtor_gid())), m_GoalRender.Companion_Default___.EncStrs(((*(_6_r).IndexInt(1)).(m_GoalWitness.Wit)).Dtor_bids())), _dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_((func() _dafny.Int {
								if (((*(_6_r).IndexInt(0)).(_dafny.Int)).Cmp(m_GoalIr.Companion_Default___.Allow()) == 0) && (m_GoalWitness.Companion_Default___.VerifyWitness(_5_p, _2_a, _3_h, (*(_6_r).IndexInt(1)).(m_GoalWitness.Wit))) {
									return _dafny.One
								}
								return _dafny.Zero
							})())))
						}
					}
				}
			}
		}
	}
	{
		return Companion_Default___.Bad()
	}
}
func (_static *CompanionStruct_Default___) RenderT(gt _dafny.Sequence) _dafny.Sequence {
	var _source0 m_GoalIr.Option = Companion_Default___.ParseG(gt)
	_ = _source0
	{
		if _source0.Is_Some() {
			var _0_g m_GoalIr.Goal = _source0.Get_().(m_GoalIr.Option_Some).V.(m_GoalIr.Goal)
			_ = _0_g
			return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(m_GoalRender.Companion_Tok_.Create_TI_(_dafny.Zero)), m_GoalRender.Companion_Default___.Render(_0_g))
		}
	}
	{
		return Companion_Default___.Bad()
	}
}

// End of class Default__
