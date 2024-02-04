package export_utils

import (
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/std/rangecheck/varuna"

	"github.com/fxamacker/cbor/v2"
)

/* A little-endian [4]uint64 array for each bls12-377 scale field variable. Note that fr.Element is in Montgomery form and should be convert to normal form with .Bits(). */
type Element [4]uint64

type ConstraintRaw struct {
	A map[int]Element `json:"a"`
	B map[int]Element `json:"b"`
	C map[int]Element `json:"c"`
}
type R1CSRaw []ConstraintRaw

func SerializeR1CS(r1cs constraint.R1CS, filePath string) error {
	r1csRaw := make(R1CSRaw, 0, r1cs.GetNbConstraints())

	for _, r1c := range r1cs.GetR1Cs() {
		c := ConstraintRaw{make(map[int]Element, len(r1c.L)), make(map[int]Element, len(r1c.R)), make(map[int]Element, len(r1c.O))}
		for _, term := range r1c.L {
			e := r1cs.GetCoefficient(int(term.CID))
			var ee fr.Element
			copy(ee[:], e[:4])
			c.A[int(term.VID)] = ee.Bits()

			var bi big.Int
			ee.BigInt(&bi)
			if bi.Cmp(fr.Modulus()) != -1 {
				panic("wft!!!")
			}
		}
		for _, term := range r1c.R {
			e := r1cs.GetCoefficient(int(term.CID))
			var ee fr.Element
			copy(ee[:], e[:4])
			c.B[int(term.VID)] = ee.Bits()

			var bi big.Int
			ee.BigInt(&bi)
			if bi.Cmp(fr.Modulus()) != -1 {
				panic("wft!!!")
			}
		}
		for _, term := range r1c.O {
			e := r1cs.GetCoefficient(int(term.CID))
			var ee fr.Element
			copy(ee[:], e[:4])
			c.C[int(term.VID)] = ee.Bits()

			var bi big.Int
			ee.BigInt(&bi)
			if bi.Cmp(fr.Modulus()) != -1 {
				panic("wft!!!")
			}
		}
		r1csRaw = append(r1csRaw, c)
	}

	{
		fR1CS, _ := os.Create(filePath)
		got, err := cbor.Marshal(&r1csRaw)
		if err != nil {
			return err
		}
		if _, err := fR1CS.Write(got); err != nil {
			return err
		}
		fR1CS.Close()
	}
	return nil
}

type AssignmentRaw struct {
	Variables          []Element `json:"variables"`
	PrimaryInputSize   uint      `json:"primary_input_size"`
	AuxiliaryInputSize uint      `json:"auxiliary_input_size"`
}

// TODO: primary_input_size and auxiliary_input_size are actually not used

func SerializeAssignment(solution *cs.R1CSSolution, filePath string) error {
	assignmentRaw := AssignmentRaw{make([]Element, 0, len(solution.W)), 0, 0}

	for _, v := range solution.W[1:] { /* omit first element since it is const value 1 */
		assignmentRaw.Variables = append(assignmentRaw.Variables, Element(v.Bits()))
	}

	{
		fAssignment, _ := os.Create(filePath)
		got, err := cbor.Marshal(&assignmentRaw)
		if err != nil {
			return err
		}
		if _, err := fAssignment.Write(got); err != nil {
			return err
		}
		fAssignment.Close()
	}
	return nil
}

type LookupRaw struct {
	Table       [][3]uint32     `json:"table"` /* Note the type of value is uint32, in case the baseLength shall not larger than 32 */
	Constraints []ConstraintRaw `json:"constraints"`
}

func SerializeLookup(lookup *varuna.Lookup, r1cs constraint.R1CS, filePath string) error {
	lookupRaw := LookupRaw{make([][3]uint32, 0, lookup.NbTable), make([]ConstraintRaw, 0, len(lookup.A))}
	for i := 0; i < lookup.NbTable; i++ {
		lookupRaw.Table = append(lookupRaw.Table, [3]uint32{uint32(i), 0, 0})
	}

	for _, lc := range lookup.A {
		c := ConstraintRaw{make(map[int]Element, len(lc)), make(map[int]Element, 0), make(map[int]Element, 0)}
		for _, term := range lc {
			e := r1cs.GetCoefficient(int(term.CID))
			var ee fr.Element
			copy(ee[:], e[:4])
			c.A[int(term.VID)] = ee.Bits()
		}
		/* no need to set B and C since they are all zeros */
		// c.B[0] = FrElement{} /* 0 */
		// c.C[0] = FrElement{} /* 0 */
		lookupRaw.Constraints = append(lookupRaw.Constraints, c)
	}

	{
		fLookup, _ := os.Create(filePath)
		got, err := cbor.Marshal(&lookupRaw)
		if err != nil {
			return err
		}
		if _, err := fLookup.Write(got); err != nil {
			return err
		}
		fLookup.Close()
	}
	return nil
}
