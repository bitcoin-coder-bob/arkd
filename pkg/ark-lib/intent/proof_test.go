package intent_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

const noteProofMessage = "test-note-closure-parity"

// TestNewIntent verifies that New constructs a valid PSBT proof for well-formed inputs and returns errors for invalid ones.
func TestNewIntent(t *testing.T) {
	validFixtures, invalidFixtures := parseProofFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, fixture := range validFixtures {
			t.Run(fixture.Name, func(t *testing.T) {
				proof, err := intent.New(fixture.Message, fixture.Inputs, fixture.Outputs)
				require.NoError(t, err)
				require.NotNil(t, proof)
				require.GreaterOrEqual(t, len(proof.Inputs), 2)
				require.GreaterOrEqual(t, len(proof.Outputs), 1)

				encodedProof, err := proof.B64Encode()
				require.NoError(t, err)
				require.NotEmpty(t, encodedProof)

				require.Equal(t, fixture.Expected, encodedProof)

				require.Equal(t, len(fixture.Outputs) > 0, proof.ContainsOutputs())

				proofInputOutpoints := proof.GetOutpoints()
				require.Len(t, proofInputOutpoints, len(fixture.Inputs))
				for i, input := range fixture.Inputs {
					require.Equal(t, *input.OutPoint, proofInputOutpoints[i])
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, fixture := range invalidFixtures {
			t.Run(fixture.Name, func(t *testing.T) {
				proof, err := intent.New(fixture.Message, fixture.Inputs, fixture.Outputs)
				require.Error(t, err)
				require.Nil(t, proof)
				require.ErrorContains(t, err, fixture.ExpectedError)
			})
		}
	})

	t.Run("BIP-322 global 0x09 field", func(t *testing.T) {
		validFixtures, _ := parseProofFixtures(t)
		for _, fixture := range validFixtures {
			t.Run(fixture.Name, func(t *testing.T) {
				proof, err := intent.New(fixture.Message, fixture.Inputs, fixture.Outputs)
				require.NoError(t, err)

				var found *psbt.Unknown
				for _, u := range proof.Unknowns {
					if len(u.Key) == 1 && u.Key[0] == 0x09 {
						found = u
						break
					}
				}
				require.NotNil(t, found, "PSBT global 0x09 field must be present")
				require.Equal(t, []byte(fixture.Message), found.Value,
					"0x09 value must equal the intent message")
			})
		}
	})
}

// TestVerifyIntent verifies that Verify accepts valid signed proofs and rejects malformed or tampered ones.
func TestVerifyIntent(t *testing.T) {
	validFixtures, invalidFixtures := parseVerifyFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, fixture := range validFixtures {
			t.Run(fixture.Name, func(t *testing.T) {
				skip := parseSkipKeys(t, fixture.SkipKeys)
				err := intent.Verify(fixture.Proof, fixture.Message, skip)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, fixture := range invalidFixtures {
			t.Run(fixture.Name, func(t *testing.T) {
				skip := parseSkipKeys(t, fixture.SkipKeys)
				err := intent.Verify(fixture.Proof, fixture.Message, skip)
				require.Error(t, err)
				require.ErrorContains(t, err, fixture.ExpectedError)
			})
		}
	})

	t.Run("notes", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			t.Run("correct control block and preimage", func(t *testing.T) {
				s := newNoteClosureSetup(t)
				p := buildNoteProof(t, s, s.cbBytes)
				setNotePreimage(t, p, 1, s.preimage)

				err := intent.Verify(serializeProof(t, p), noteProofMessage, nil)
				require.NoError(t, err)
			})
		})

		t.Run("invalid", func(t *testing.T) {
			t.Run("wrong parity bit in control block", func(t *testing.T) {
				s := newNoteClosureSetup(t)
				corrupted := make([]byte, len(s.cbBytes))
				copy(corrupted, s.cbBytes)
				corrupted[0] ^= 0x01

				p := buildNoteProof(t, s, corrupted)
				// Parity is checked before the preimage, so no preimage needed.
				err := intent.Verify(serializeProof(t, p), noteProofMessage, nil)
				require.ErrorContains(t, err, "parity")
			})

			t.Run("wrong x-coordinate from tampered merkle path", func(t *testing.T) {
				s := newNoteClosureSetup(t)
				fakeNode := make([]byte, 32)
				_, err := rand.Read(fakeNode)
				require.NoError(t, err)

				corrupted := append(append([]byte{}, s.cbBytes...), fakeNode...)
				p := buildNoteProof(t, s, corrupted)
				err = intent.Verify(serializeProof(t, p), noteProofMessage, nil)
				require.ErrorContains(t, err, "invalid control block")
			})

			t.Run("missing preimage", func(t *testing.T) {
				s := newNoteClosureSetup(t)
				p := buildNoteProof(t, s, s.cbBytes)
				// No preimage set; control block is valid so execution reaches preimage check.

				err := intent.Verify(serializeProof(t, p), noteProofMessage, nil)
				require.ErrorContains(t, err, "preimage")
			})

			t.Run("wrong preimage", func(t *testing.T) {
				s := newNoteClosureSetup(t)
				p := buildNoteProof(t, s, s.cbBytes)

				wrong := make([]byte, 32)
				_, err := rand.Read(wrong)
				require.NoError(t, err)
				setNotePreimage(t, p, 1, wrong)

				err = intent.Verify(serializeProof(t, p), noteProofMessage, nil)
				require.ErrorContains(t, err, "preimage")
			})
		})
	})
}

// TestIntentGetOutpoints checks that GetOutpoints returns the correct slice of outpoints, excluding the toSpend input.
func TestIntentGetOutpoints(t *testing.T) {
	t.Run("zero inputs", func(t *testing.T) {
		ptxWithZeroInputs := psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{},
			},
		}
		proof := intent.Proof{Packet: ptxWithZeroInputs}
		outpoints := proof.GetOutpoints()
		require.Len(t, outpoints, 0)
	})

	t.Run("one input", func(t *testing.T) {
		ptxWithOneInput := psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{}}},
			},
		}
		proof := intent.Proof{Packet: ptxWithOneInput}
		outpoints := proof.GetOutpoints()
		require.Len(t, outpoints, 0)
	})
}

// TestIntentAmounts verifies that out of range input and output amounts are rejected before any
// consumer casts them to uint64, and that the zero-valued toSpend input is excluded from the fee.
func TestIntentAmounts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("fee is sum of inputs minus sum of outputs", func(t *testing.T) {
			proof := newAmountsProof(0, []int64{8000, 2000}, []int64{6000, 3800})

			require.NoError(t, proof.ValidateAmounts())

			fees, err := proof.Fees()
			require.NoError(t, err)
			require.Equal(t, int64(200), fees)
		})

		t.Run("toSpend input does not contribute to the fee", func(t *testing.T) {
			proof := newAmountsProof(0, []int64{8000}, []int64{7800})

			fees, err := proof.Fees()
			require.NoError(t, err)
			require.Equal(t, int64(200), fees)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("negative output amount", func(t *testing.T) {
			proof := newAmountsProof(0, []int64{8000}, []int64{-9990961, 9999340})

			err := proof.ValidateAmounts()
			require.ErrorContains(t, err, "invalid amount for output 0")

			_, err = proof.Fees()
			require.ErrorContains(t, err, "invalid amount for output 0")
		})

		t.Run("output amount above max satoshi", func(t *testing.T) {
			proof := newAmountsProof(0, []int64{8000}, []int64{btcutil.MaxSatoshi + 1})

			require.ErrorContains(t, proof.ValidateAmounts(), "invalid amount for output 0")
		})

		t.Run("negative input amount", func(t *testing.T) {
			proof := newAmountsProof(0, []int64{-8000}, []int64{7800})

			require.ErrorContains(t, proof.ValidateAmounts(), "invalid amount for input 1")
		})

		t.Run("non-zero toSpend input", func(t *testing.T) {
			// the toSpend value is not committed to by the signatures, it must stay zero
			proof := newAmountsProof(10_000_000, []int64{8579}, []int64{330, 9999340})

			err := proof.ValidateAmounts()
			require.ErrorContains(t, err, "invalid amount for toSpend input")

			_, err = proof.Fees()
			require.ErrorContains(t, err, "invalid amount for toSpend input")
		})

		t.Run("missing witness utxo", func(t *testing.T) {
			proof := newAmountsProof(0, []int64{8000}, []int64{7800})
			proof.Inputs[1].WitnessUtxo = nil

			require.ErrorContains(t, proof.ValidateAmounts(), "missing witness utxo for input 1")
		})

		t.Run("outputs exceed inputs", func(t *testing.T) {
			proof := newAmountsProof(0, []int64{8000}, []int64{9000})

			_, err := proof.Fees()
			require.ErrorContains(t, err, "sum of inputs is smaller than sum of outputs")
		})

		t.Run("sum of outputs overflows int64", func(t *testing.T) {
			// individually valid amounts can still overflow the accumulator
			count := int(int64(math.MaxInt64)/int64(btcutil.MaxSatoshi)) + 1
			outputValues := make([]int64, count)
			for i := range outputValues {
				outputValues[i] = btcutil.MaxSatoshi
			}
			proof := newAmountsProof(0, []int64{8000}, outputValues)

			require.NoError(t, proof.ValidateAmounts())

			_, err := proof.Fees()
			require.ErrorContains(t, err, "sum of outputs overflows")
		})
	})

	// a negative amount paired with a matching positive one keeps the int64 sums balanced,
	// so the pair has to be caught per output rather than on the totals
	t.Run("offsetting amounts survive a base64 round trip", func(t *testing.T) {
		proof := newAmountsProof(0, []int64{8579}, []int64{-9990961, 9999340})
		encoded := serializeProof(t, &proof)

		ptx, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
		require.NoError(t, err)

		decoded := intent.Proof{Packet: *ptx}
		require.ErrorContains(t, decoded.ValidateAmounts(), "invalid amount for output 0")

		_, err = decoded.Fees()
		require.ErrorContains(t, err, "invalid amount for output 0")

		require.Error(t, intent.Verify(encoded, "", nil))
	})

	// Both shapes below are built so that every total a caller might check still looks
	// correct. Each subtest first asserts the property that made the shape slip past the
	// totals, then asserts that validation rejects it anyway. If a guard is ever removed
	// the second half fails while the first half keeps documenting why that matters.
	t.Run("shapes that balance on every total", func(t *testing.T) {
		t.Run("negative output offset by a larger positive one", func(t *testing.T) {
			const (
				inputValue    = int64(8579)
				offchainValue = int64(-9990961)
				onchainValue  = int64(9999340)
			)
			proof := newAmountsProof(0, []int64{inputValue}, []int64{offchainValue, onchainValue})

			// the int64 total is a plausible 200 sat fee
			require.Equal(t, int64(8379), offchainValue+onchainValue)
			require.Equal(t, int64(200), inputValue-(offchainValue+onchainValue))

			// and the uint64 total wraps back to the very same number, so summing the
			// outputs after the cast agrees with the int64 view
			sum := uint64(0)
			for _, out := range proof.UnsignedTx.TxOut {
				sum += uint64(out.Value)
			}
			require.Equal(t, uint64(8379), sum)

			// the cast turns the negative output into a value no floor or ceiling catches
			cast := uint64(proof.UnsignedTx.TxOut[0].Value)
			require.Greater(t, cast, uint64(btcutil.MaxSatoshi))

			require.ErrorContains(t, proof.ValidateAmounts(), "invalid amount for output 0")
			_, err := proof.Fees()
			require.ErrorContains(t, err, "invalid amount for output 0")
		})

		t.Run("inflated toSpend input with every amount in range", func(t *testing.T) {
			proof := newAmountsProof(10_000_000, []int64{8579}, []int64{330, 9999340})

			// no per amount check can catch this one: every value is positive and within
			// range, only the zero-valued toSpend input has been overstated
			for i, in := range proof.Inputs {
				require.Positive(t, in.WitnessUtxo.Value+1, "input %d", i)
				require.LessOrEqual(t, in.WitnessUtxo.Value, int64(btcutil.MaxSatoshi))
			}
			for i, out := range proof.UnsignedTx.TxOut {
				require.Positive(t, out.Value, "output %d", i)
				require.LessOrEqual(t, out.Value, int64(btcutil.MaxSatoshi))
			}

			// the toSpend value is what buys the headroom: it is not committed to by any
			// signature, so counting it would let the outputs exceed the real inputs
			require.Greater(t, int64(330+9999340), int64(8579))

			require.ErrorContains(t, proof.ValidateAmounts(), "invalid amount for toSpend input")
			_, err := proof.Fees()
			require.ErrorContains(t, err, "invalid amount for toSpend input")
		})

		t.Run("same shape with an honest toSpend cannot fund the outputs", func(t *testing.T) {
			// drop the overstated toSpend and the outputs no longer fit in the inputs
			proof := newAmountsProof(0, []int64{8579}, []int64{330, 9999340})

			require.NoError(t, proof.ValidateAmounts())

			_, err := proof.Fees()
			require.ErrorContains(t, err, "sum of inputs is smaller than sum of outputs")
		})
	})
}

type proofFixture struct {
	Name     string
	Inputs   []intent.Input
	Outputs  []*wire.TxOut
	Message  string
	Expected string
}

type invalidProofFixture struct {
	Name          string
	Inputs        []intent.Input
	Outputs       []*wire.TxOut
	Message       string
	ExpectedError string
}

type jsonProofFixture struct {
	Name   string `json:"name"`
	Inputs []struct {
		Txid        string `json:"txid"`
		Vout        uint32 `json:"vout"`
		Sequence    uint32 `json:"sequence,omitempty"`
		WitnessUtxo *struct {
			Script string `json:"script"`
			Amount int64  `json:"amount"`
		} `json:"witness_utxo,omitempty"`
	} `json:"inputs"`
	Outputs []struct {
		Script string `json:"script"`
		Amount int64  `json:"amount"`
	} `json:"outputs"`
	Message       string `json:"message"`
	Expected      string `json:"expected"`
	ExpectedError string `json:"expected_error"`
}

type proofFixturesJSON struct {
	Valid   []jsonProofFixture `json:"valid"`
	Invalid []jsonProofFixture `json:"invalid"`
}

func parseProofFixtures(t *testing.T) ([]proofFixture, []invalidProofFixture) {
	file, err := os.ReadFile("testdata/proof_fixtures.json")
	require.NoError(t, err)

	var jsonData proofFixturesJSON
	err = json.Unmarshal(file, &jsonData)
	require.NoError(t, err)

	validFixtures := make([]proofFixture, 0, len(jsonData.Valid))
	for _, jsonFixture := range jsonData.Valid {
		fixture := proofFixture{
			Name:     jsonFixture.Name,
			Message:  jsonFixture.Message,
			Expected: jsonFixture.Expected,
		}

		fixture.Inputs = make([]intent.Input, 0, len(jsonFixture.Inputs))
		for _, jsonInput := range jsonFixture.Inputs {
			txidBytes, err := hex.DecodeString(jsonInput.Txid)
			require.NoError(t, err)
			var txidHash chainhash.Hash
			copy(txidHash[:], txidBytes)

			scriptBytes, err := hex.DecodeString(jsonInput.WitnessUtxo.Script)
			require.NoError(t, err)

			fixture.Inputs = append(fixture.Inputs, intent.Input{
				OutPoint: &wire.OutPoint{
					Hash:  txidHash,
					Index: jsonInput.Vout,
				},
				Sequence: jsonInput.Sequence,
				WitnessUtxo: &wire.TxOut{
					Value:    jsonInput.WitnessUtxo.Amount,
					PkScript: scriptBytes,
				},
			})
		}

		fixture.Outputs = make([]*wire.TxOut, 0, len(jsonFixture.Outputs))
		for _, jsonOutput := range jsonFixture.Outputs {
			scriptBytes, err := hex.DecodeString(jsonOutput.Script)
			require.NoError(t, err)

			fixture.Outputs = append(fixture.Outputs, &wire.TxOut{
				Value:    jsonOutput.Amount,
				PkScript: scriptBytes,
			})
		}

		validFixtures = append(validFixtures, fixture)
	}

	invalidFixtures := make([]invalidProofFixture, 0, len(jsonData.Invalid))
	for _, jsonFixture := range jsonData.Invalid {
		fixture := invalidProofFixture{
			Name:          jsonFixture.Name,
			Message:       jsonFixture.Message,
			ExpectedError: jsonFixture.ExpectedError,
		}

		fixture.Inputs = make([]intent.Input, 0, len(jsonFixture.Inputs))
		for _, jsonInput := range jsonFixture.Inputs {
			input := intent.Input{
				Sequence: jsonInput.Sequence,
			}

			if len(jsonInput.Txid) > 0 {
				txidBytes, err := hex.DecodeString(jsonInput.Txid)
				require.NoError(t, err)
				var txidHash chainhash.Hash
				copy(txidHash[:], txidBytes)
				input.OutPoint = &wire.OutPoint{
					Hash:  txidHash,
					Index: jsonInput.Vout,
				}
			}

			if jsonInput.WitnessUtxo != nil {
				scriptBytes, err := hex.DecodeString(jsonInput.WitnessUtxo.Script)
				require.NoError(t, err)
				input.WitnessUtxo = &wire.TxOut{
					Value:    jsonInput.WitnessUtxo.Amount,
					PkScript: scriptBytes,
				}
			}
			fixture.Inputs = append(fixture.Inputs, input)
		}

		fixture.Outputs = make([]*wire.TxOut, 0, len(jsonFixture.Outputs))
		for _, jsonOutput := range jsonFixture.Outputs {
			scriptBytes, err := hex.DecodeString(jsonOutput.Script)
			require.NoError(t, err)

			fixture.Outputs = append(fixture.Outputs, &wire.TxOut{
				Value:    jsonOutput.Amount,
				PkScript: scriptBytes,
			})
		}

		invalidFixtures = append(invalidFixtures, fixture)
	}
	return validFixtures, invalidFixtures
}

type verifyFixture struct {
	Name          string   `json:"name"`
	Proof         string   `json:"proof"`
	Message       string   `json:"message"`
	SkipKeys      []string `json:"skip_keys,omitempty"`
	ExpectedError string   `json:"expected_error"`
}

type verifyFixturesJSON struct {
	Valid   []verifyFixture `json:"valid"`
	Invalid []verifyFixture `json:"invalid"`
}

func parseVerifyFixtures(t *testing.T) ([]verifyFixture, []verifyFixture) {
	file, err := os.ReadFile("testdata/verify_fixtures.json")
	require.NoError(t, err)

	var jsonData verifyFixturesJSON
	err = json.Unmarshal(file, &jsonData)
	require.NoError(t, err)

	return jsonData.Valid, jsonData.Invalid
}

func parseSkipKeys(t *testing.T, keys []string) []*btcec.PublicKey {
	t.Helper()
	if len(keys) == 0 {
		return nil
	}
	result := make([]*btcec.PublicKey, 0, len(keys))
	for _, k := range keys {
		b, err := hex.DecodeString(k)
		require.NoError(t, err)
		pk, err := schnorr.ParsePubKey(b)
		require.NoError(t, err)
		result = append(result, pk)
	}
	return result
}

type noteClosureSetup struct {
	preimage   []byte
	noteScript []byte
	p2trScript []byte
	cbBytes    []byte
}

func newNoteClosureSetup(t *testing.T) noteClosureSetup {
	t.Helper()

	preimage := make([]byte, 32)
	_, err := rand.Read(preimage)
	require.NoError(t, err)

	hash := sha256.Sum256(preimage)
	nc := &note.NoteClosure{PreimageHash: hash}

	noteScript, err := nc.Script()
	require.NoError(t, err)

	leaf := txscript.NewBaseTapLeaf(noteScript)
	tapTree := txscript.AssembleTaprootScriptTree(leaf)
	root := tapTree.RootNode.TapHash()

	unspendableKey := script.UnspendableKey()
	taprootKey := txscript.ComputeTaprootOutputKey(unspendableKey, root[:])

	p2trScript, err := script.P2TRScript(taprootKey)
	require.NoError(t, err)

	leafIndex := tapTree.LeafProofIndex[leaf.TapHash()]
	cb := tapTree.LeafMerkleProofs[leafIndex].ToControlBlock(unspendableKey)
	cbBytes, err := cb.ToBytes()
	require.NoError(t, err)

	return noteClosureSetup{
		preimage:   preimage,
		noteScript: noteScript,
		p2trScript: p2trScript,
		cbBytes:    cbBytes,
	}
}

// buildNoteProof creates an intent proof with a single note closure as the ownership input.
// cb is the raw control block bytes to embed (may be a corrupted copy for negative tests).
func buildNoteProof(t *testing.T, s noteClosureSetup, cb []byte) *intent.Proof {
	t.Helper()

	var prevHash [32]byte
	_, err := rand.Read(prevHash[:])
	require.NoError(t, err)

	p, err := intent.New(noteProofMessage, []intent.Input{{
		OutPoint:    &wire.OutPoint{Hash: prevHash, Index: 0},
		WitnessUtxo: &wire.TxOut{Value: 1_000, PkScript: s.p2trScript},
	}}, nil)
	require.NoError(t, err)

	// Index 0 is the toSpend spending input; index 1 is the ownership input.
	p.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: cb,
		Script:       s.noteScript,
		LeafVersion:  txscript.BaseLeafVersion,
	}}

	return p
}

// setNotePreimage stores the preimage in the PSBT's condition witness field for the given input.
func setNotePreimage(t *testing.T, p *intent.Proof, inputIndex int, preimage []byte) {
	t.Helper()
	err := txutils.SetArkPsbtField(
		&p.Packet, inputIndex, txutils.ConditionWitnessField,
		wire.TxWitness{preimage},
	)
	require.NoError(t, err)
}

func serializeProof(t *testing.T, p *intent.Proof) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, p.Serialize(&buf))
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// newAmountsProof builds a proof with the shape expected by ValidateAmounts and Fees: a leading
// toSpend input followed by the inputs proving ownership. Only the amounts are meaningful, the
// scripts and outpoints are placeholders.
func newAmountsProof(toSpendValue int64, inputValues, outputValues []int64) intent.Proof {
	txIns := []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{}}}
	pInputs := []psbt.PInput{
		{WitnessUtxo: &wire.TxOut{Value: toSpendValue, PkScript: []byte{txscript.OP_TRUE}}},
	}

	for i, value := range inputValues {
		txIns = append(txIns, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Index: uint32(i + 1)},
		})
		pInputs = append(pInputs, psbt.PInput{
			WitnessUtxo: &wire.TxOut{Value: value, PkScript: []byte{txscript.OP_TRUE}},
		})
	}

	txOuts := make([]*wire.TxOut, 0, len(outputValues))
	pOutputs := make([]psbt.POutput, 0, len(outputValues))
	for _, value := range outputValues {
		txOuts = append(txOuts, &wire.TxOut{Value: value, PkScript: []byte{txscript.OP_TRUE}})
		pOutputs = append(pOutputs, psbt.POutput{})
	}

	return intent.Proof{Packet: psbt.Packet{
		UnsignedTx: &wire.MsgTx{Version: 2, TxIn: txIns, TxOut: txOuts},
		Inputs:     pInputs,
		Outputs:    pOutputs,
	}}
}
