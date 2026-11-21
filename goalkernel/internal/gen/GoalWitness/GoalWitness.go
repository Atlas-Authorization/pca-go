// Package GoalWitness
// Dafny module GoalWitness compiled into Go

package GoalWitness

import (
	m_GoalCompile "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/GoalCompile"
	m_GoalIr "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/GoalIr"
	m__System "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/System_"
	_dafny "github.com/Atlas-Authorization/pca-go/goalkernel/internal/gen/dafny"
	os "os"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__
var _ m_GoalIr.Dummy__
var _ m_GoalCompile.Dummy__

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
	return "GoalWitness.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) Applicable(cs _dafny.Sequence, gid _dafny.Sequence, verb _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((cs).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if m_GoalIr.Companion_Default___.AppliesL(((cs).Select(0).(m_GoalCompile.LCeil)).Dtor_sel(), gid, verb) {
				return _dafny.SeqOf(((cs).Select(0).(m_GoalCompile.LCeil)).Dtor_bid())
			}
			return _dafny.SeqOf()
		})())
		var _in0 _dafny.Sequence = (cs).Drop(1)
		_ = _in0
		var _in1 _dafny.Sequence = gid
		_ = _in1
		var _in2 _dafny.Sequence = verb
		_ = _in2
		cs = _in0
		gid = _in1
		verb = _in2
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) FindAllow(ps _dafny.Sequence, ceils _dafny.Sequence, dg m_GoalIr.Delegation, a m_GoalIr.Act, h m_GoalIr.Hist) m_GoalIr.Option {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((ps).Cardinality())).Sign() == 0 {
		return m_GoalIr.Companion_Option_.Create_None_()
	} else if (m_GoalCompile.Companion_Default___.PredDec((ps).Select(0).(m_GoalCompile.LPred), ceils, dg, a, h)).Cmp(m_GoalIr.Companion_Default___.Allow()) == 0 {
		return m_GoalIr.Companion_Option_.Create_Some_((ps).Select(0).(m_GoalCompile.LPred))
	} else {
		var _in0 _dafny.Sequence = (ps).Drop(1)
		_ = _in0
		var _in1 _dafny.Sequence = ceils
		_ = _in1
		var _in2 m_GoalIr.Delegation = dg
		_ = _in2
		var _in3 m_GoalIr.Act = a
		_ = _in3
		var _in4 m_GoalIr.Hist = h
		_ = _in4
		ps = _in0
		ceils = _in1
		dg = _in2
		a = _in3
		h = _in4
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) DecideW(p m_GoalCompile.Pol, a m_GoalIr.Act, h m_GoalIr.Hist) _dafny.Tuple {
	var _0_d _dafny.Int = m_GoalCompile.Companion_Default___.DP(p, a, h)
	_ = _0_d
	if (_0_d).Cmp(m_GoalIr.Companion_Default___.Allow()) == 0 {
		var _source0 m_GoalIr.Option = Companion_Default___.FindAllow((p).Dtor_preds(), (p).Dtor_ceils(), (p).Dtor_deleg(), a, h)
		_ = _source0
		{
			if _source0.Is_Some() {
				var _1_pr m_GoalCompile.LPred = _source0.Get_().(m_GoalIr.Option_Some).V.(m_GoalCompile.LPred)
				_ = _1_pr
				return _dafny.TupleOf(m_GoalIr.Companion_Default___.Allow(), Companion_Wit_.Create_Wit_((_1_pr).Dtor_gid(), Companion_Default___.Applicable((p).Dtor_ceils(), (_1_pr).Dtor_gid(), (a).Dtor_verb())))
			}
		}
		{
			return _dafny.TupleOf(m_GoalIr.Companion_Default___.Deny(), Companion_Wit_.Create_Wit_(_dafny.UnicodeSeqOfUtf8Bytes(""), _dafny.SeqOf()))
		}
	} else {
		return _dafny.TupleOf(_0_d, Companion_Wit_.Create_Wit_(_dafny.UnicodeSeqOfUtf8Bytes(""), _dafny.SeqOf()))
	}
}
func (_static *CompanionStruct_Default___) AnyPredAllows(ps _dafny.Sequence, gid _dafny.Sequence, ceils _dafny.Sequence, dg m_GoalIr.Delegation, a m_GoalIr.Act, h m_GoalIr.Hist) bool {
	return ((_dafny.IntOfUint32((ps).Cardinality())).Sign() == 1) && (((_dafny.Companion_Sequence_.Equal(((ps).Select(0).(m_GoalCompile.LPred)).Dtor_gid(), gid)) && ((m_GoalCompile.Companion_Default___.PredDec((ps).Select(0).(m_GoalCompile.LPred), ceils, dg, a, h)).Cmp(m_GoalIr.Companion_Default___.Allow()) == 0)) || (Companion_Default___.AnyPredAllows((ps).Drop(1), gid, ceils, dg, a, h)))
}
func (_static *CompanionStruct_Default___) VerifyWitness(p m_GoalCompile.Pol, a m_GoalIr.Act, h m_GoalIr.Hist, w Wit) bool {
	return (((((m_GoalIr.Companion_Default___.ValidityDec((p).Dtor_validity(), (p).Dtor_deleg(), a, h)).Cmp(m_GoalIr.Companion_Default___.Allow()) == 0) && ((m_GoalCompile.Companion_Default___.ProhDecP((p).Dtor_prohs(), a, h)).Cmp(m_GoalIr.Companion_Default___.Allow()) == 0)) && ((m_GoalCompile.Companion_Default___.EscDecP((p).Dtor_escs(), a, h)).Cmp(m_GoalIr.Companion_Default___.Allow()) == 0)) && (Companion_Default___.AnyPredAllows((p).Dtor_preds(), (w).Dtor_gid(), (p).Dtor_ceils(), (p).Dtor_deleg(), a, h))) && (_dafny.Companion_Sequence_.Equal((w).Dtor_bids(), Companion_Default___.Applicable((p).Dtor_ceils(), (w).Dtor_gid(), (a).Dtor_verb())))
}
func (_static *CompanionStruct_Default___) PepAllows(d _dafny.Int, ans m_GoalIr.Option, pd _dafny.Sequence, ad _dafny.Sequence, hh _dafny.Sequence) bool {
	return ((d).Cmp(m_GoalIr.Companion_Default___.Allow()) == 0) || (((((((d).Cmp(m_GoalIr.Companion_Default___.Escalate()) == 0) && ((ans).Is_Some())) && (((ans).Dtor_v().(Answer)).Dtor_sigOk())) && (_dafny.Companion_Sequence_.Equal(((ans).Dtor_v().(Answer)).Dtor_policyDigest(), pd))) && (_dafny.Companion_Sequence_.Equal(((ans).Dtor_v().(Answer)).Dtor_actionDigest(), ad))) && (_dafny.Companion_Sequence_.Equal(((ans).Dtor_v().(Answer)).Dtor_histHead(), hh)))
}

// End of class Default__

// Definition of datatype Wit
type Wit struct {
	Data_Wit_
}

func (_this Wit) Get_() Data_Wit_ {
	return _this.Data_Wit_
}

type Data_Wit_ interface {
	isWit()
}

type CompanionStruct_Wit_ struct {
}

var Companion_Wit_ = CompanionStruct_Wit_{}

type Wit_Wit struct {
	Gid  _dafny.Sequence
	Bids _dafny.Sequence
}

func (Wit_Wit) isWit() {}

func (CompanionStruct_Wit_) Create_Wit_(Gid _dafny.Sequence, Bids _dafny.Sequence) Wit {
	return Wit{Wit_Wit{Gid, Bids}}
}

func (_this Wit) Is_Wit() bool {
	_, ok := _this.Get_().(Wit_Wit)
	return ok
}

func (CompanionStruct_Wit_) Default() Wit {
	return Companion_Wit_.Create_Wit_(_dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this Wit) Dtor_gid() _dafny.Sequence {
	return _this.Get_().(Wit_Wit).Gid
}

func (_this Wit) Dtor_bids() _dafny.Sequence {
	return _this.Get_().(Wit_Wit).Bids
}

func (_this Wit) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Wit_Wit:
		{
			return "GoalWitness.Wit.Wit" + "(" + data.Gid.VerbatimString(true) + ", " + _dafny.String(data.Bids) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Wit) Equals(other Wit) bool {
	switch data1 := _this.Get_().(type) {
	case Wit_Wit:
		{
			data2, ok := other.Get_().(Wit_Wit)
			return ok && data1.Gid.Equals(data2.Gid) && data1.Bids.Equals(data2.Bids)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Wit) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Wit)
	return ok && _this.Equals(typed)
}

func Type_Wit_() _dafny.TypeDescriptor {
	return type_Wit_{}
}

type type_Wit_ struct {
}

func (_this type_Wit_) Default() interface{} {
	return Companion_Wit_.Default()
}

func (_this type_Wit_) String() string {
	return "GoalWitness.Wit"
}
func (_this Wit) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Wit{}

// End of datatype Wit

// Definition of datatype Answer
type Answer struct {
	Data_Answer_
}

func (_this Answer) Get_() Data_Answer_ {
	return _this.Data_Answer_
}

type Data_Answer_ interface {
	isAnswer()
}

type CompanionStruct_Answer_ struct {
}

var Companion_Answer_ = CompanionStruct_Answer_{}

type Answer_Answer struct {
	SigOk        bool
	PolicyDigest _dafny.Sequence
	ActionDigest _dafny.Sequence
	HistHead     _dafny.Sequence
}

func (Answer_Answer) isAnswer() {}

func (CompanionStruct_Answer_) Create_Answer_(SigOk bool, PolicyDigest _dafny.Sequence, ActionDigest _dafny.Sequence, HistHead _dafny.Sequence) Answer {
	return Answer{Answer_Answer{SigOk, PolicyDigest, ActionDigest, HistHead}}
}

func (_this Answer) Is_Answer() bool {
	_, ok := _this.Get_().(Answer_Answer)
	return ok
}

func (CompanionStruct_Answer_) Default() Answer {
	return Companion_Answer_.Create_Answer_(false, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this Answer) Dtor_sigOk() bool {
	return _this.Get_().(Answer_Answer).SigOk
}

func (_this Answer) Dtor_policyDigest() _dafny.Sequence {
	return _this.Get_().(Answer_Answer).PolicyDigest
}

func (_this Answer) Dtor_actionDigest() _dafny.Sequence {
	return _this.Get_().(Answer_Answer).ActionDigest
}

func (_this Answer) Dtor_histHead() _dafny.Sequence {
	return _this.Get_().(Answer_Answer).HistHead
}

func (_this Answer) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Answer_Answer:
		{
			return "GoalWitness.Answer.Answer" + "(" + _dafny.String(data.SigOk) + ", " + data.PolicyDigest.VerbatimString(true) + ", " + data.ActionDigest.VerbatimString(true) + ", " + data.HistHead.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Answer) Equals(other Answer) bool {
	switch data1 := _this.Get_().(type) {
	case Answer_Answer:
		{
			data2, ok := other.Get_().(Answer_Answer)
			return ok && data1.SigOk == data2.SigOk && data1.PolicyDigest.Equals(data2.PolicyDigest) && data1.ActionDigest.Equals(data2.ActionDigest) && data1.HistHead.Equals(data2.HistHead)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Answer) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Answer)
	return ok && _this.Equals(typed)
}

func Type_Answer_() _dafny.TypeDescriptor {
	return type_Answer_{}
}

type type_Answer_ struct {
}

func (_this type_Answer_) Default() interface{} {
	return Companion_Answer_.Default()
}

func (_this type_Answer_) String() string {
	return "GoalWitness.Answer"
}
func (_this Answer) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Answer{}

// End of datatype Answer
