package export_utils

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/field/pool"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/std/rangecheck/varuna"
)

type FrElement struct {
	fr.Element
}

func (z FrElement) MarshalJSON() ([]byte, error) {
	var b [32]byte
	binary.BigEndian.PutUint64(b[24:32], z.Element[0])
	binary.BigEndian.PutUint64(b[16:24], z.Element[1])
	binary.BigEndian.PutUint64(b[8:16], z.Element[2])
	binary.BigEndian.PutUint64(b[0:8], z.Element[3])

	vv := pool.BigInt.Get()
	vv.SetBytes(b[:])
	bs := []byte("\"" + vv.Text(10) + "\"")
	pool.BigInt.Put(vv)
	return bs, nil
}

type ConstraintRaw struct {
	A map[int]FrElement `json:"a"`
	B map[int]FrElement `json:"b"`
	C map[int]FrElement `json:"c"`
}
type R1CSRaw []ConstraintRaw

func SerializeR1CS(r1cs constraint.R1CS, filePath string) error {
	r1csRaw := make(R1CSRaw, 0, r1cs.GetNbConstraints())

	for _, r1c := range r1cs.GetR1Cs() {
		c := ConstraintRaw{make(map[int]FrElement, len(r1c.L)), make(map[int]FrElement, len(r1c.R)), make(map[int]FrElement, len(r1c.O))}
		for _, term := range r1c.L {
			e := r1cs.GetCoefficient(int(term.CID))
			var ee fr.Element
			copy(ee[:], e[:4])
			c.A[int(term.VID)] = FrElement{ee}
		}
		for _, term := range r1c.R {
			e := r1cs.GetCoefficient(int(term.CID))
			var ee fr.Element
			copy(ee[:], e[:4])
			c.B[int(term.VID)] = FrElement{ee}
		}
		for _, term := range r1c.O {
			e := r1cs.GetCoefficient(int(term.CID))
			var ee fr.Element
			copy(ee[:], e[:4])
			c.C[int(term.VID)] = FrElement{ee}
		}
		r1csRaw = append(r1csRaw, c)
	}

	{
		fR1CS, _ := os.Create(filePath)
		got, err := json.MarshalIndent(&r1csRaw, "", "\t") /* @imlk: this line cost 7GB ram */
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
	Variables          []FrElement `json:"variables"`
	PrimaryInputSize   uint        `json:"primary_input_size"`
	AuxiliaryInputSize uint        `json:"auxiliary_input_size"`
}

// TODO: primary_input_size and auxiliary_input_size are actually not used

func SerializeAssignment(solution *cs.R1CSSolution, filePath string) error {
	assignmentRaw := AssignmentRaw{make([]FrElement, 0, len(solution.W)), 0, 0}

	for _, v := range solution.W {
		assignmentRaw.Variables = append(assignmentRaw.Variables, FrElement{v})
	}

	{
		fAssignment, _ := os.Create(filePath)
		got, err := json.MarshalIndent(&assignmentRaw, "", "\t")
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
	Table       [][3]string     `json:"table"`
	Constraints []ConstraintRaw `json:"constraints"`
}

func SerializeLookup(lookup *varuna.Lookup, r1cs constraint.R1CS, filePath string) error {
	lookupRaw := LookupRaw{make([][3]string, 0, lookup.NbTable), make([]ConstraintRaw, 0, len(lookup.A))}
	for i := 0; i < lookup.NbTable; i++ {
		lookupRaw.Table = append(lookupRaw.Table, [3]string{strconv.Itoa(i), "0", "0"})
	}

	for _, lc := range lookup.A {
		c := ConstraintRaw{make(map[int]FrElement, len(lc)), make(map[int]FrElement, 0), make(map[int]FrElement, 0)}
		for _, term := range lc {
			e := r1cs.GetCoefficient(int(term.CID))
			var ee fr.Element
			copy(ee[:], e[:4])
			c.A[int(term.VID)] = FrElement{ee}
		}
		// TODO: debug term.VID is 4294967295
		/* no need to set B and C since they are all zeros */
		// c.B[0] = FrElement{} /* 0 */
		// c.C[0] = FrElement{} /* 0 */
		lookupRaw.Constraints = append(lookupRaw.Constraints, c)
	}

	{
		fLookup, _ := os.Create(filePath)
		got, err := json.MarshalIndent(&lookupRaw, "", "\t")
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
