// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateSwapkitChainflipSignature(t *testing.T) {
	sig, err := base64.StdEncoding.DecodeString("+LiZmhz/AD3eYaqMS7OAlTcpz95wMLBZFDQyx7w30K006dwGp+XyTjHFP6CwyCS75xbMx0CRW0zSUIEHLR8cUg==")
	require.NoError(t, err)

	paymentRequest := &messages.BTCPaymentRequestRequest{
		RecipientName: "SWAPKIT (CHAINFLIP)",
		Nonce:         nil,
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{
				Memo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_{
					CoinPurchaseMemo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo{
						CoinType: 0,
						Amount:   "0.0313324 BTC",
						Address:  "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",
					},
				},
			},
		},
		TotalAmount: 0,
		Signature:   sig,
	}

	pubkeys := []string{
		"02483844345304ad315d93cb24f03f525275fb6166a49428fddd4a45014898340d",
	}

	for _, testCase := range []struct {
		name             string
		outputValueBytes []byte
	}{
		{
			name:             "little endian 8 bytes",
			outputValueBytes: binary.LittleEndian.AppendUint64(nil, 1000000000000000000),
		},
		{
			name:             "big endian 8 bytes",
			outputValueBytes: binary.BigEndian.AppendUint64(nil, 1000000000000000000),
		},
		{
			name: "little endian 32 bytes",
			outputValueBytes: func() []byte {
				result := make([]byte, 32)
				binary.LittleEndian.PutUint64(result, 1000000000000000000)
				return result
			}(),
		},
		{
			name: "big endian 32 bytes",
			outputValueBytes: func() []byte {
				result := make([]byte, 32)
				binary.BigEndian.PutUint64(result[24:], 1000000000000000000)
				return result
			}(),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			sighash, err := ComputePaymentRequestSighashBytes(
				paymentRequest,
				60,
				testCase.outputValueBytes,
				"0xf5e10380213880111522dd0efd3dbb45b9f62bcc",
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

			require.Equal(t, 1, matchCount)
		})
	}
}
