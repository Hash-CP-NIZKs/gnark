package varuna

import (
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/logger"
)

func init() {
	solver.RegisterHint(DecomposeHint)
}

type ctxCheckerKey struct{}

func NewVarunaRangechecker(api frontend.API) *varunaChecker {
	kv, ok := api.Compiler().(kvstore.Store)
	if !ok {
		panic("builder should implement key-value store")
	}
	ch := kv.GetKeyValue(ctxCheckerKey{})
	if ch != nil {
		if cht, ok := ch.(*varunaChecker); ok {
			return cht
		} else {
			panic("stored rangechecker is not valid")
		}
	}
	cht := &varunaChecker{}
	kv.SetKeyValue(ctxCheckerKey{}, cht)
	api.Compiler().Defer(cht.handleVarunaRangeCheck)
	return cht
}

type checkedVariable struct {
	v    frontend.Variable
	bits int
}

type varunaChecker struct {
	collected []checkedVariable
	closed    bool
	lookups   Lookup
}

type Lookup struct {
	NbTable int                           // the size of the lookup table, which is 1 << baseLength
	A       []constraint.LinearExpression // the A matrix of all the lookup constraints
}

func (c *varunaChecker) Check(in frontend.Variable, bits int) {
	if c.closed {
		panic("checker already closed")
	}
	c.collected = append(c.collected, checkedVariable{v: in, bits: bits})
}

func getOptimalBasewidth(api frontend.API, collected []checkedVariable) int {
	return optimalWidth(nbR1CSConstraints, collected)
}

func optimalWidth(countFn func(baseLength int, collected []checkedVariable) int, collected []checkedVariable) int {
	min := math.MaxInt64
	minVal := 0
	for j := 2; j < 18; j++ {
		current := countFn(j, collected)
		if current < min {
			min = current
			minVal = j
		}
	}

	return minVal
}

func nbR1CSConstraints(baseLength int, collected []checkedVariable) int {
	nbDecomposed := 0
	for i := range collected {
		nbDecomposed += int(decompSize(collected[i].bits, baseLength))
	}
	eqs := len(collected)       // correctness of decomposition
	nbRight := nbDecomposed     // inverse per decomposed
	nbleft := (1 << baseLength) // div per table
	return nbleft + nbRight + eqs + 1
}

func decompSize(varSize int, limbSize int) int {
	return (varSize + limbSize - 1) / limbSize
}

func (c *varunaChecker) handleVarunaRangeCheck(api frontend.API) error {
	if c.closed {
		return nil
	}
	defer func() { c.closed = true }()
	if len(c.collected) == 0 {
		return nil
	}
	log := logger.Logger().With().Logger()

	uniqueBits := map[int]int{}
	for _, v := range c.collected {
		uniqueBits[v.bits] = uniqueBits[v.bits] + 1
	}
	log.Debug().Msg(fmt.Sprintf("unique bits to range check: %v", uniqueBits))

	baseLength := getOptimalBasewidth(api, c.collected)
	// decompose into smaller limbs
	decomposed := make([]frontend.Variable, 0, len(c.collected))
	collected := make([]frontend.Variable, len(c.collected))
	base := new(big.Int).Lsh(big.NewInt(1), uint(baseLength))
	for i := range c.collected {
		// collect all vars for commitment input
		collected[i] = c.collected[i].v
		// decompose value into limbs
		nbLimbs := decompSize(c.collected[i].bits, baseLength)
		limbs, err := api.Compiler().NewHint(DecomposeHint, int(nbLimbs), c.collected[i].bits, baseLength, c.collected[i].v)
		if err != nil {
			panic(fmt.Sprintf("decompose %v", err))
		}
		// store all limbs for counting
		decomposed = append(decomposed, limbs...)
		// check that limbs are correct. We check the sizes of the limbs later
		var composed frontend.Variable = 0
		for j := range limbs {
			composed = api.Add(composed, api.Mul(limbs[j], new(big.Int).Exp(base, big.NewInt(int64(j)), nil)))
		}
		api.AssertIsEqual(composed, c.collected[i].v)
	}
	nbTable := 1 << baseLength
	log.Debug().Int("selected baseLength", baseLength).Int("number of rangecheck variable", len(c.collected)).Int("number of (decomposed)lookup variable", len(decomposed)).Msg("decompose done")

	c.lookups.NbTable = nbTable
	c.lookups.A = make([]constraint.LinearExpression, 0)

	for _, v := range decomposed {
		t := api.Compiler().ToCanonicalVariable(v)
		if l, ok := t.(constraint.LinearExpression); ok {
			c.lookups.A = append(c.lookups.A, l)
		} else {
			return fmt.Errorf("unhandled type of variable %T", v)
		}
	}
	return nil
}

func GetLookupByBuilder(api frontend.Builder) *Lookup {
	kv, ok := api.Compiler().(kvstore.Store)
	if !ok {
		panic("builder should implement key-value store")
	}
	ch := kv.GetKeyValue(ctxCheckerKey{})
	if ch != nil {
		if cht, ok := ch.(*varunaChecker); ok {
			if !cht.closed {
				panic("checker is not closed")
			}
			return &cht.lookups
		} else {
			panic("stored rangechecker is not valid")
		}
	}
	panic("rangechecker not found")
}

// DecomposeHint is a hint used for range checking with commitment. It
// decomposes large variables into chunks which can be individually range-check
// in the native range.
func DecomposeHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("input must be 3 elements")
	}
	if !inputs[0].IsUint64() || !inputs[1].IsUint64() {
		return fmt.Errorf("first two inputs have to be uint64")
	}
	varSize := int(inputs[0].Int64())
	limbSize := int(inputs[1].Int64())
	val := inputs[2]
	nbLimbs := decompSize(varSize, limbSize)
	if len(outputs) != nbLimbs {
		return fmt.Errorf("need %d outputs instead to decompose", nbLimbs)
	}
	base := new(big.Int).Lsh(big.NewInt(1), uint(limbSize))
	tmp := new(big.Int).Set(val)
	for i := 0; i < len(outputs); i++ {
		outputs[i].Mod(tmp, base)
		tmp.Rsh(tmp, uint(limbSize))
	}
	return nil
}
