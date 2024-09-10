package ethapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"reflect"
	"testing"
)

func staticAccount() account {
	var (
		key, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
		to     = crypto.PubkeyToAddress(key.PublicKey)
	)
	return account{key, to}
}

func newStaticAccounts() []account {
	var (
		key1, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7b")
		to1     = crypto.PubkeyToAddress(key1.PublicKey)
		key2, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7c")
		to2     = crypto.PubkeyToAddress(key2.PublicKey)
		key3, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7d")
		to3     = crypto.PubkeyToAddress(key3.PublicKey)
	)
	return []account{{key1, to1}, {key2, to2}, {key3, to3}}
}

var nonceMap map[account]uint64

func signTXForBytes(hex string, baseFee *big.Int, acc account, To *common.Address) hexutil.Bytes {
	_, b := signTX(hex, baseFee, acc, To)
	return b
}

func signTX(hex string, baseFee *big.Int, acc account, To *common.Address) (*types.Transaction, hexutil.Bytes) {
	if nonceMap == nil {
		nonceMap = map[account]uint64{}
	}

	nonce, exist := nonceMap[acc]
	if !exist {
		nonce = 0
	}

	var (
		code, _     = hexutil.Decode(hex) // 0x12.....
		createTX, _ = types.SignTx(types.NewTx(&types.LegacyTx{Nonce: nonce, To: To, Gas: 1000000, GasPrice: baseFee, Data: code}),
			types.HomesteadSigner{}, acc.key)
		rawCreateTX, _ = createTX.MarshalBinary()
	)
	nonceMap[acc] = nonce + 1
	return createTX, rawCreateTX
}

func TestCallBundle(t *testing.T) {
	t.Parallel()

	// Initialize test accounts
	staticAcc := staticAccount()
	accounts := newStaticAccounts()
	var (
		genesis = &core.Genesis{
			Config: params.MergedTestChainConfig,
			Alloc: core.GenesisAlloc{
				accounts[0].addr: {Balance: big.NewInt(params.Ether)},
				accounts[1].addr: {Balance: big.NewInt(params.Ether)},
				accounts[2].addr: {Balance: big.NewInt(params.Ether)},
				staticAcc.addr:   {Balance: big.NewInt(params.Ether)},
			},
		}
		genBlocks = 10
		signer    = types.HomesteadSigner{}
	)

	contractAddr := crypto.CreateAddress(staticAcc.addr, 0)
	baseFees := make([]*big.Int, genBlocks)
	backend := newTestBackend(t, genBlocks, genesis, beacon.New(ethash.NewFaker()), func(i int, b *core.BlockGen) {
		baseFees[i] = b.BaseFee()
		tx, _ := types.SignTx(types.NewTx(&types.LegacyTx{Nonce: uint64(i), To: &accounts[1].addr, Value: big.NewInt(1000), Gas: params.TxGas, GasPrice: b.BaseFee(), Data: nil}), signer, accounts[0].key)
		b.AddTx(tx)
		b.SetPoS()
	})

	UseAccessListTrue := true
	// randomAccounts := newAccounts(3)

	api := NewBundleAPI(backend, backend.chain)
	tests := []struct {
		args      CallBundleArgs
		wantValue []string
		want      string
		expectErr error
	}{
		// Call Function
		{
			args: CallBundleArgs{
				Txs: []hexutil.Bytes{
					// PUSH5 0x9876543210
					// PUSH0
					// SSTORE <- For ACL test
					// PUSH5 0x0123456789
					// PUSH0
					// MSTORE
					// PUSH1 0x20
					// PUSH0
					// RETURN
					signTXForBytes("0x7f6498765432105f556401234567895f5260205ff30000000000000000000000005f5260145ff3",
						baseFees[1], staticAcc, nil),
					signTXForBytes("0x00", baseFees[1], accounts[1], &contractAddr)},
				UseAccessList: &UseAccessListTrue,
			},
			want:      "{\"bundleGasPrice\":\"500494222\",\"bundleHash\":\"0xb466022602abcbf737e3857373fc26c27998b435b7da96a88f1b79e8aec6224a\",\"coinbaseDiff\":\"50362231088750\",\"ethSentToCoinbase\":\"0\",\"gasFees\":\"50362231088750\",\"results\":[{\"aclList\":[],\"coinbaseDiff\":\"28778417765000\",\"ethSentToCoinbase\":\"0\",\"fromAddress\":\"0x703c4b2bD70c169f5717101CaeE543299Fc946C7\",\"gasFees\":\"28778417765000\",\"gasPrice\":\"500494222\",\"gasUsed\":57500,\"logs\":null,\"toAddress\":\"0x\",\"txHash\":\"0x616b4abef6e7c71b5f4d15bf60d81f66ca9d0441fc2ba8990be7abe0774996e8\",\"value\":\"0x6498765432105f556401234567895f5260205ff3\"},{\"aclList\":[{\"address\":\"0x35658f7b2a9e7701e65e7a654659eb1c481d1dc5\",\"storageKeys\":[\"0x0000000000000000000000000000000000000000000000000000000000000000\"]}],\"coinbaseDiff\":\"21583813323750\",\"ethSentToCoinbase\":\"0\",\"fromAddress\":\"0x4B9a56b239936d9A60eB973728B88bed008666D6\",\"gasFees\":\"21583813323750\",\"gasPrice\":\"500494222\",\"gasUsed\":43125,\"logs\":null,\"toAddress\":\"0x35658f7b2a9E7701e65E7a654659eb1C481d1dC5\",\"txHash\":\"0xf40bcc7f42702f484c47f14327c895c7dcf379a28b2c19a800a10b1616e670b0\",\"value\":\"0x0000000000000000000000000000000000000000000000000000000123456789\"}],\"stateBlockNumber\":10,\"totalGasUsed\":100625}",
			expectErr: nil,
		},
	}
	for i, tc := range tests {
		result, err := api.CallBundle(context.Background(), tc.args)
		if tc.expectErr != nil {
			if err == nil {
				t.Errorf("test %d: want error %v, have nothing", i, tc.expectErr)
				continue
			}
			if !errors.Is(err, tc.expectErr) {
				// Second try
				if !reflect.DeepEqual(err, tc.expectErr) {
					t.Errorf("test %d: error mismatch, want %v, have %v", i, tc.expectErr, err)
				}
			}
			continue
		}
		if err != nil {
			t.Errorf("test %d: want no error, have %v", i, err)
			continue
		}

		if len(tc.wantValue) > 0 {
			results, exist := result["results"]
			if !exist {
				t.Errorf("test %d, results is not exist have %v\n", i, result)
				continue
			}
			rawResults := results.([]map[string]interface{})
			for idx, res := range rawResults {
				value := res["value"].(string)
				if tc.wantValue[idx] != value {
					t.Errorf("test %d, value mismatch have\n%v\n, want\n%v\n", i, value, tc.wantValue[idx])
				}
			}

			continue
		}

		//var wantMap map[string]interface{}
		//_ = json.Unmarshal([]byte(tc.want), &wantMap)
		//delete(result, "bundleHash")
		resultMap, _ := json.Marshal(result)

		if !reflect.DeepEqual(string(resultMap), tc.want) {
			t.Errorf("test %d, result mismatch, have\n%v\n, want\n%v\n", i, string(resultMap), tc.want)
		}
	}
}
