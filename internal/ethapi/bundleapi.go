package ethapi

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
	"math/big"
	"sync"
	"time"
)

// DoCallWithStateDB
// StateDB를 지정하여 그 Context상에서는 실행한 결과값을 추출하기 위해
// DoCall가 별개로 다시 작성한 코드이다.
func DoCallWithStateDB(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	args.GasPrice = (*hexutil.Big)(header.BaseFee)
	err := args.CallDefaults(b.RPCGasCap(), header.BaseFee, b.ChainConfig().ChainID)
	msg := args.ToMessage(header.BaseFee)
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil, b.ChainConfig(), state)
	evm := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true}, &blockCtx)

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	if err != nil {
		return result, fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit)
	}
	return result, nil
}

// ---------------------------------------------------------------- FlashBots ----------------------------------------------------------------

// BundleAPI offers an API for accepting bundled transactions
type BundleAPI struct {
	b     Backend
	chain *core.BlockChain

	cacheBlockNum *big.Int
	cacheStateDB  *state.StateDB
	cacheParent   *types.Header
	cacheMutex    sync.Mutex
	cachedTxs     types.Transactions
}

// NewBundleAPI creates a new Tx Bundle API instance.
func NewBundleAPI(b Backend, chain *core.BlockChain) *BundleAPI {
	return &BundleAPI{b: b, chain: chain}
}

// CallBundleArgs represents the arguments for a call.
type CallBundleArgs struct {
	Txs            []hexutil.Bytes    `json:"txs"`
	Coinbase       *string            `json:"coinbase"`
	Timestamp      *uint64            `json:"timestamp"`
	Timeout        *int64             `json:"timeout"`
	GasLimit       *uint64            `json:"gasLimit"`
	Difficulty     *big.Int           `json:"difficulty"`
	BaseFee        *big.Int           `json:"baseFee"`
	HeadCalls      []*TransactionArgs `json:"headCalls"`      // Author: SGT
	Calls          []*TransactionArgs `json:"calls"`          // Author: SGT
	RichAddress    []*string          `json:"richAddress"`    // Author: SGT
	StorageAddress []*string          `json:"storageAddress"` // Author: SGT
	StorageKey     []*string          `json:"storageKey"`     // Author: SGT
	StorageValue   []*string          `json:"storageValue"`   // Author: SGT
	UseAccessList  *bool              `json:"UseAccessList"`  // Author: SGT
	UseQuoter      *bool              `json:"UseQuoter"`      // Author: SGT
	QuoterCode     *string            `json:"QuoterCode"`
}

// CallBundle will simulate a bundle of transactions at the top of a given block
// number with the state of another (or the same) block. This can be used to
// simulate future blocks with the current state, or it can be used to simulate
// a past block.
// The sender is responsible for signing the transactions and using the correct
// nonce and ensuring validity
func (s *BundleAPI) CallBundle(ctx context.Context, args CallBundleArgs) (map[string]interface{}, error) {
	var txs types.Transactions

	if args.Txs != nil {
		for _, encodedTx := range args.Txs {
			tx := new(types.Transaction)
			if err := tx.UnmarshalBinary(encodedTx); err != nil {
				return nil, err
			}
			txs = append(txs, tx)
		}
	}
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	timeoutMilliSeconds := int64(3000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// TODO: 무조건 최신 블록만 사용하도록 수정했음 확인
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, latest)
	if state == nil || err != nil {
		return nil, err
	}
	// TODO: 무조건 최신 블록만 사용하도록 수정했음 확인
	blockNumber := big.NewInt(parent.Number.Int64() + 1)

	// Author: SGT
	// This code adds 1000 ethers each to RichAddress
	if args.RichAddress != nil && len(args.RichAddress) > 0 {
		GiveEther := big.NewInt(0)
		GiveEther.SetString("10000000000000000000000", 10) // 1000 ethers
		GiveEtherNew, _ := uint256.FromBig(GiveEther)
		for _, richAddr := range args.RichAddress {
			state.SetBalance(common.HexToAddress(*richAddr), GiveEtherNew, tracing.BalanceChangeUnspecified)
			if args.StorageAddress != nil && args.StorageKey != nil && args.StorageValue != nil {
				for i, storageAddr := range args.StorageAddress {
					state.SetState(
						common.HexToAddress(*storageAddr),
						common.HexToHash(*args.StorageKey[i]),
						common.HexToHash(*args.StorageValue[i]))
				}
			}
		}
	}

	if args.UseQuoter != nil && *args.UseQuoter {
		var QuoterCode []byte
		if args.QuoterCode != nil && len(*args.QuoterCode) > 0 {
			QuoterCode, _ = hexutil.Decode(*args.QuoterCode)
		} else {
			rawCode := "0x34600114600b576103fb565b5f3560001a565b005b603c565b604a565b6086565b608f565b60c9565b61014f565b6101c8565b610251565b6102cb565b60013560601c315f5260205ff35b80601a013560f01c5f5f828085601c015f375f856002013560e01c86600101355f1a1b866006013560601c5af19101601c019081355f1a575f5ffd5b60016001355f1a565b7f0902f1ac000000000000000000000000000000000000000000000000000000005f5260405f60045f5f856001013560601c5af15060405ff35b7f128acb08000000000000000000000000000000000000000000000000000000005f52306004525f602452806002013560e01c81600101355f1a1b60445273fffd8963efd1fc6a506488495d951d5263988d2560645260a0608452601560a45280601a013560c452602460f81b60d85260405f60d95f5f856006013560601c5af160205ff35b7f128acb08000000000000000000000000000000000000000000000000000000005f52306004526001602452806002013560e01c81600101355f1a1b6044526401000276a460645260a0608452601560a45280601a013560c452600460f81b60d85260405f60d95f5f856006013560601c5af160206020f35b7f128acb08000000000000000000000000000000000000000000000000000000005f52306004525f602452806002013560e01c81600101355f1a1b5f0360445273fffd8963efd1fc6a506488495d951d5263988d2560645260a0608452601560a45280601a013560c452602460f81b60d85260405f60d95f5f856006013560601c5af160206020f35b7f128acb08000000000000000000000000000000000000000000000000000000005f52306004526001602452806002013560e01c81600101355f1a1b5f036044526401000276a460645260a0608452601560a45280601a013560c452600460f81b60d85260405f60d95f5f856006013560601c5af160205ff35b7f3850c7bd000000000000000000000000000000000000000000000000000000005f52602061010060045f5f856001013560601c5af1507f1a686502000000000000000000000000000000000000000000000000000000005f52602061012060045f5f856001013560601c5af1507fddca3f43000000000000000000000000000000000000000000000000000000005f52602061014060045f5f856001013560601c5af1507f70a08231000000000000000000000000000000000000000000000000000000005f52806001013560601c600452602061016060245f5f856015013560601c5af1507f70a08231000000000000000000000000000000000000000000000000000000005f52806001013560601c600452602061018060245f5f856029013560601c5af15060a0610100f35b7fa9059cbb000000000000000000000000000000000000000000000000000000005f52336004526098355f1a356024525f5f60445f5f60843560601c5af16012575f5ffd"
			QuoterCode, _ = hexutil.Decode(rawCode)
		}
		quoterAddr := common.HexToAddress("0xF000000000000000000000000000000000000000")
		state.SetCode(quoterAddr, QuoterCode)
	}

	coinbase := parent.Coinbase

	exBlobGas := eip4844.CalcExcessBlobGas(*parent.ExcessBlobGas, *parent.BlobGasUsed)
	header := &types.Header{
		ParentHash:    parent.Hash(),
		Number:        blockNumber,
		GasLimit:      parent.GasLimit,
		Time:          parent.Time + 2,
		Difficulty:    parent.Difficulty,
		Coinbase:      parent.Coinbase,
		BaseFee:       eip1559.CalcBaseFee(s.b.ChainConfig(), parent, parent.Time+2),
		ExcessBlobGas: &exBlobGas,
	}

	vmconfig := vm.Config{}

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	results := []map[string]interface{}{}
	coinbaseBalanceBefore := state.GetBalance(coinbase)

	// Author: SGT
	// This code execute calls for reading before TX simulation.
	if args.HeadCalls != nil {
		for _, call := range args.HeadCalls {
			if call == nil {
				results = append(results, map[string]interface{}{})
				continue
			}

			result, err := DoCallWithStateDB(ctx, s.b, *call, state, header, s.b.RPCEVMTimeout(), s.b.RPCGasCap())
			if err != nil {
				return nil, err
			}
			jsonResult := map[string]interface{}{}

			if result.Err != nil {
				jsonResult["error"] = result.Err.Error()
				revert := result.Revert()
				if len(revert) > 0 {
					jsonResult["revert"] = string(revert)
				}
			} else {
				dst := make([]byte, hex.EncodedLen(len(result.Return())))
				hex.Encode(dst, result.Return())
				jsonResult["value"] = "0x" + string(dst)
			}
			results = append(results, jsonResult)
		}
	}

	var bundleHash []byte
	signer := types.MakeSigner(s.b.ChainConfig(), blockNumber, header.Time)
	var totalGasUsed uint64
	gasFees := new(big.Int)
	for i, tx := range txs {
		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		coinbaseBalanceBeforeTx := state.GetBalance(coinbase)
		state.SetTxContext(tx.Hash(), i)

		var aclList types.AccessList
		var receipt *types.Receipt
		var result *core.ExecutionResult

		if args.UseAccessList != nil && *args.UseAccessList {
			aclList, receipt, result, err = ApplyTransactionWithACLResult(
				s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed)
		} else {
			receipt, result, err = ApplyTransactionWithResult(
				s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
		}

		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		txHash := tx.Hash().String()
		from, err := types.Sender(signer, tx)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		to := "0x"
		if tx.To() != nil {
			to = tx.To().String()
		}

		jsonResult := map[string]interface{}{
			"txHash":      txHash,
			"gasUsed":     receipt.GasUsed,
			"fromAddress": from.String(),
			"toAddress":   to,
			"logs":        receipt.Logs,
			"aclList":     aclList,
		}
		totalGasUsed += receipt.GasUsed
		gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)
		gasFees.Add(gasFees, gasFeesTx)
		bundleHash = crypto.Keccak256(tx.Hash().Bytes())
		//bundleHash.Write(tx.Hash().Bytes())
		if result.Err != nil {
			jsonResult["error"] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				jsonResult["revert"] = string(revert)
			}
		} else {
			dst := make([]byte, hex.EncodedLen(len(result.Return())))
			hex.Encode(dst, result.Return())
			jsonResult["value"] = "0x" + string(dst)
		}
		coinbaseDiffTx := new(big.Int).Sub(state.GetBalance(coinbase).ToBig(), coinbaseBalanceBeforeTx.ToBig())
		jsonResult["coinbaseDiff"] = coinbaseDiffTx.String()
		jsonResult["gasFees"] = gasFeesTx.String()
		jsonResult["ethSentToCoinbase"] = new(big.Int).Sub(coinbaseDiffTx, gasFeesTx).String()
		jsonResult["gasPrice"] = new(big.Int).Div(coinbaseDiffTx, big.NewInt(int64(receipt.GasUsed))).String()
		jsonResult["gasUsed"] = receipt.GasUsed
		results = append(results, jsonResult)
	}

	// Author: SGT
	// This code execute calls for reading with current context.
	if args.Calls != nil {
		for _, call := range args.Calls {
			if call == nil {
				results = append(results, map[string]interface{}{})
				continue
			}
			result, err := DoCallWithStateDB(ctx, s.b, *call, state, header, s.b.RPCEVMTimeout(), s.b.RPCGasCap())
			if err != nil {
				return nil, err
			}
			jsonResult := map[string]interface{}{}

			if result.Err != nil {
				jsonResult["error"] = result.Err.Error()
				revert := result.Revert()
				if len(revert) > 0 {
					jsonResult["revert"] = string(revert)
				}
			} else {
				dst := make([]byte, hex.EncodedLen(len(result.Return())))
				hex.Encode(dst, result.Return())
				jsonResult["value"] = "0x" + string(dst)
			}
			results = append(results, jsonResult)
		}
	}

	ret := map[string]interface{}{}
	ret["results"] = results
	coinbaseDiff := new(big.Int).Sub(state.GetBalance(coinbase).ToBig(), coinbaseBalanceBefore.ToBig())
	ret["coinbaseDiff"] = coinbaseDiff.String()
	ret["gasFees"] = gasFees.String()
	ret["ethSentToCoinbase"] = new(big.Int).Sub(coinbaseDiff, gasFees).String()
	if totalGasUsed > 0 {
		ret["bundleGasPrice"] = new(big.Int).Div(coinbaseDiff, big.NewInt(int64(totalGasUsed))).String()
	}
	ret["totalGasUsed"] = totalGasUsed
	ret["stateBlockNumber"] = parent.Number.Int64()

	ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash)
	return ret, nil
}

func applyTransactionWithResult(msg *core.Message, config *params.ChainConfig, bc core.ChainContext, author *common.Address, gp *core.GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, *core.ExecutionResult, error) {
	// Create a new context to be used in the EVM environment.
	txContext := core.NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := core.ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), header.Number.Uint64(), header.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = header.Hash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, result, err
}
func ApplyTransactionWithResult(config *params.ChainConfig, bc core.ChainContext, author *common.Address, gp *core.GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, *core.ExecutionResult, error) {
	//msg, err := tx.AsMessage(types.MakeSigner(config, header.Number), header.BaseFee)
	msg, err := core.TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := core.NewEVMBlockContext(header, bc, author, config, statedb)
	txContext := core.NewEVMTxContext(msg)
	vmenv := vm.NewEVM(blockContext, txContext, statedb, config, cfg)
	return applyTransactionWithResult(msg, config, bc, author, gp, statedb, header, tx, usedGas, vmenv)
}
func ApplyTransactionWithACLResult(
	config *params.ChainConfig,
	bc core.ChainContext,
	author *common.Address,
	gp *core.GasPool,
	statedb *state.StateDB,
	header *types.Header,
	tx *types.Transaction,
	usedGas *uint64) (types.AccessList, *types.Receipt, *core.ExecutionResult, error) {

	//msg, err := tx.AsMessage(types.MakeSigner(config, header.Number), header.BaseFee)
	msg, err := core.TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, nil, nil, err
	}

	var to common.Address
	if tx.To() != nil {
		to = *tx.To()
	} else {
		to = crypto.CreateAddress(msg.From, tx.Nonce())
	}

	isPostMerge := header.Difficulty.Cmp(common.Big0) == 0
	// Retrieve the precompiles since they don't need to be added to the access list
	precompiles := vm.ActivePrecompiles(config.Rules(header.Number, isPostMerge, header.Time))
	// 비어있는 ACL을 가져오기 위해 prevTracer를 선언한다.
	preTracer := logger.NewAccessListTracer(nil, msg.From, to, precompiles)
	// Retrieve the current access list to expand
	accessList := preTracer.AccessList()
	// ACL을 가져오기 위해 prevTracer를 선언한다.
	tracer := logger.NewAccessListTracer(accessList, msg.From, to, precompiles)
	// print log
	log.Trace("Creating access list", "input", accessList)
	// trace용 config
	traceConfig := vm.Config{Tracer: tracer.Hooks(), NoBaseFee: true}
	// Create a new context to be used in the EVM environment
	blockContext := core.NewEVMBlockContext(header, bc, author, config, statedb)
	txContext := core.NewEVMTxContext(msg)
	vmenv := vm.NewEVM(blockContext, txContext, statedb, config, traceConfig)
	r1, r2, err := applyTransactionWithResult(msg, config, bc, author, gp, statedb, header, tx, usedGas, vmenv)
	return tracer.AccessList(), r1, r2, err
}

func (s *BundleAPI) BaseFee(ctx context.Context) (*hexutil.Big, error) {
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	state, parentHead, err := s.b.StateAndHeaderByNumberOrHash(ctx, latest)
	if state == nil || err != nil {
		return nil, err
	}
	baseFee := eip1559.CalcBaseFee(s.b.ChainConfig(), parentHead, parentHead.Time+2)
	return (*hexutil.Big)(baseFee), nil
}
