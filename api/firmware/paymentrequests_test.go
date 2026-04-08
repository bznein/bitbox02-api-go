// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"encoding/binary"
	"encoding/base64"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateSwapkitNearSignature(t *testing.T) {
	sig, err := base64.StdEncoding.DecodeString("0sHo3wWNyavVaOgryHtgyps4bcBKBEh3kK8G8iTMLONHVazkTekd9bMOLA4IzcNJcdlrCrElcrj7L4sSvk6Ykg==")
	if err != nil {
		panic(err)
	}

	paymentRequest := &messages.BTCPaymentRequestRequest{
		RecipientName: "SWAPKIT (NEAR)",
		Nonce:         nil,
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{
				Memo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_{
					CoinPurchaseMemo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo{
						CoinType: 0,
						Amount:   "0.03127916 BTC",
						Address:  "bc1qsf4wt3v2gr0vyfngra8vvs4xlqrz8kelttmzp3",
					},
				},
			},
		},
		TotalAmount: 0,
		Signature:   sig,
	}

	pubkeys := []string{
		"03098cba9cde720171796a5c58cb774b0cd19deb62e9b51df5967aefeba34632ff",
		"02b985055ff600a6b1d30ddf6020693ce9fe8db55e5a0e27dc6144eb48040ce517",
		"02bf5740a2b794b33d73358d7313e9cb260058f3ac6c886fcc388d9f3f0b48a90d",
	}

	outputValueBigEndian := make([]byte, 32)
	binary.BigEndian.PutUint64(outputValueBigEndian[24:], 1000000000000000000)

	outputValueLittleEndian := make([]byte, 32)
	binary.LittleEndian.PutUint64(outputValueLittleEndian, 1000000000000000000)

	for _, tc := range []struct {
		name        string
		outputValue []byte
	}{
		{
			name:        "big endian",
			outputValue: outputValueBigEndian,
		},
		{
			name:        "little endian",
			outputValue: outputValueLittleEndian,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sighash, err := ComputePaymentRequestSighashBytes(
				paymentRequest,
				60,
				tc.outputValue,
				"0x05F0819b7e1683C4829B412f1862B4ECb3E503cE",
			)
			require.NoError(t, err)

			matchCount := 0
			for _, pubkeyHex := range pubkeys {
				pubKey, err := btcec.ParsePubKey(unhex(pubkeyHex))
				require.NoError(t, err)
				if parseECDSASignature(t, paymentRequest.Signature).Verify(sighash, pubKey) {
					matchCount++
				}
			}

			require.Equalf(
				t,
				1,
				matchCount,
				"SWAPKIT (NEAR) fixture signature should verify against exactly one allowed signer for sighash %x",
				sighash,
			)
		})
	}
}
