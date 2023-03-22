/**
 * Copyright (C) 2021 The poly network Authors
 * This file is part of The poly network library.
 *
 * The poly network is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The poly network is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the poly network.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package voter

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/polynetwork/poly/core/types"
	"math/big"
	"strings"
	"sync"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/eth-contracts/go_abi/eccm_abi"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	autils "github.com/polynetwork/poly/native/service/utils"
	polygonZk "github.com/polynetwork/polygonZK-sdk/client"
	"github.com/polynetwork/side-voter/config"
	"github.com/polynetwork/side-voter/pkg/db"
	"github.com/polynetwork/side-voter/pkg/log"
	"github.com/polynetwork/side-voter/polygon_zk_abi"
)

type PolygonZkClient struct {
	EthClient *ethclient.Client
	RpcClient *polygonZk.Client
}

type Voter struct {
	polySdk           *sdk.PolySdk
	signer            *sdk.Account
	conf              *config.Config
	bdb               *db.BoltDB
	clients           []*PolygonZkClient
	contracts         []*eccm_abi.EthCrossChainManager
	contractAddr      ethcommon.Address
	crossChainTopicID ethcommon.Hash
	idx               int

	l1clients      []*rpc.Client
	l1contracts    []*polygon_zk_abi.PolygonZkAbiCaller
	l1contractAddr ethcommon.Address
	l1idx          int

	sync.Mutex
}

func New(polySdk *sdk.PolySdk, signer *sdk.Account, conf *config.Config) *Voter {
	return &Voter{polySdk: polySdk, signer: signer, conf: conf}
}

func (v *Voter) Init() (err error) {
	clients := make([]*PolygonZkClient, 0)
	for _, node := range v.conf.SideConfig.RestURL {
		ethClient, err := ethclient.Dial(node)
		if err != nil {
			log.Fatalf("ethclient.Dial failed:%v", err)
		}
		rpcClient, err := polygonZk.NewPolygonZkClient(node)
		if err != nil {
			log.Fatalf("rpc.Dial failed:%v", err)
		}
		clients = append(clients, &PolygonZkClient{ethClient, rpcClient})
	}
	v.clients = clients

	bdb, err := db.NewBoltDB(v.conf.BoltDbPath)
	if err != nil {
		return
	}

	v.bdb = bdb

	v.contractAddr = ethcommon.HexToAddress(v.conf.SideConfig.ECCMContractAddress)
	ethCrossChainManagerAbiParsed, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return
	}
	if event, ok := ethCrossChainManagerAbiParsed.Events["CrossChainEvent"]; !ok {
		return fmt.Errorf("CrossChainEvent no tin ethCrossChainManagerAbiParsed.Events")
	} else {
		v.crossChainTopicID = event.ID
	}

	v.contracts = make([]*eccm_abi.EthCrossChainManager, len(clients))
	for i := 0; i < len(v.clients); i++ {
		contract, err := eccm_abi.NewEthCrossChainManager(v.contractAddr, v.clients[i].EthClient)
		if err != nil {
			return err
		}
		v.contracts[i] = contract
	}

	v.l1contractAddr = ethcommon.HexToAddress(v.conf.SideConfig.L1ContractAddress)
	l1clients := make([]*rpc.Client, 0)
	l1contracts := make([]*polygon_zk_abi.PolygonZkAbiCaller, 0)
	for _, node := range v.conf.SideConfig.L1URL {
		ethClient, err := ethclient.Dial(node)
		if err != nil {
			log.Fatalf("ethclient.Dial l1 failed:%v", err)
		}
		contract, err := polygon_zk_abi.NewPolygonZkAbiCaller(v.l1contractAddr, ethClient)
		if err != nil {
			log.Fatalf("NewZKEthAbiCaller l1 failed:%v", err)
		}
		rpcClient, err := rpc.Dial(node)
		if err != nil {
			log.Fatalf("rpc.Dial l1 failed:%v", err)
		}

		l1contracts = append(l1contracts, contract)
		l1clients = append(l1clients, rpcClient)
	}
	v.l1clients = l1clients
	v.l1contracts = l1contracts

	return
}

func (v *Voter) StartReplenish(ctx context.Context) {
	var nextPolyHeight uint64
	if v.conf.ForceConfig.PolyHeight > 0 {
		nextPolyHeight = v.conf.ForceConfig.PolyHeight
	} else {
		h, err := v.polySdk.GetCurrentBlockHeight()
		if err != nil {
			panic(fmt.Sprintf("v.polySdk.GetCurrentBlockHeight failed:%v", err))
		}
		nextPolyHeight = uint64(h)
		log.Infof("start from current poly height:%d", h)
	}
	ticker := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-ticker.C:
			h, err := v.polySdk.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("v.polySdk.GetCurrentBlockHeight failed:%v", err)
				continue
			}
			height := uint64(h)
			log.Infof("current poly height:%d", height)
			if height < nextPolyHeight {
				continue
			}

			for nextPolyHeight <= height {
				select {
				case <-ctx.Done():
					return
				default:
				}
				log.Infof("handling poly height:%d", nextPolyHeight)
				events, err := v.polySdk.GetSmartContractEventByBlock(uint32(nextPolyHeight))
				if err != nil {
					log.Errorf("poly failed to fetch smart contract events for height %d, err %v", height, err)
					continue
				}
				txHashList := make([]interface{}, 0)
				for _, event := range events {
					for _, notify := range event.Notify {
						if notify.ContractAddress != autils.ReplenishContractAddress.ToHexString() {
							continue
						}
						states, ok := notify.States.([]interface{})
						if !ok || states[0].(string) != "ReplenishTx" {
							continue
						}

						chainId := states[2].(float64)
						if uint64(chainId) == v.conf.SideConfig.SideChainId {
							txHashes := states[1].([]interface{})
							txHashList = append(txHashList, txHashes...)
						}
					}
				}

				l1Batch, _, err := v.getL1FinalizedBatch(ctx)
				if err != nil {
					log.Error("replenish getL1FinalizedBatch err", err)
					v.changeL1Endpoint()
					continue
				}

				for _, txHash := range txHashList {
					err = v.fetchLockDepositEventByTxHash(txHash.(string), l1Batch)
					if err != nil {
						log.Errorf("fetchLockDepositEventByTxHash failed:%v", err)
						//change endpoint and retry
						v.changeEndpoint()
						continue
					}
				}
				nextPolyHeight++
			}
		}
	}
}

func (v *Voter) StartVoter(ctx context.Context) {
	nextSideHeight := v.bdb.GetSideHeight()
	if v.conf.ForceConfig.SideHeight > 0 {
		nextSideHeight = v.conf.ForceConfig.SideHeight
	}
	nextL1Batch := v.bdb.GetL1Batch()
	if v.conf.ForceConfig.L1Batch > 0 {
		nextL1Batch = v.conf.ForceConfig.L1Batch
	}
	var batchLength uint64 = 1
	if v.conf.SideConfig.Batch > 0 {
		batchLength = v.conf.SideConfig.Batch
	}
	ticker := time.NewTicker(time.Second * 12)
	for {
		select {
		case <-ticker.C:
			l1Batch, l1Height, err := v.getL1FinalizedBatch(ctx)
			if err != nil {
				log.Error("getL1FinalizedBatch err", err)
				v.changeL1Endpoint()
				continue
			}
			log.Infof("l1Batch: %v, l1Height: %v, nextL1Batch: %v", l1Batch, l1Height, nextL1Batch)
			if l1Batch < nextL1Batch {
				continue
			}
			txHash, err := v.getZkLatestBatchTx(l1Batch, nextL1Batch)
			if err != nil {
				log.Error("getZkLatestBatchTx err", err)
				v.changeEndpoint()
				continue
			}
			if txHash == (ethcommon.Hash{}) {
				log.Infof("l1 batch [%v,%v] tx is empty", nextL1Batch, l1Batch)
				nextL1Batch = l1Batch + 1
				err = v.bdb.UpdateL1Batch(nextL1Batch)
				if err != nil {
					log.Errorf("UpdateL1Batch failed:%v", err)
				}
				continue
			}
			receipt, err := v.clients[v.idx].EthClient.TransactionReceipt(ctx, txHash)
			if err != nil {
				log.Errorf("TransactionReceipt err, txHash: %v, err: %v", txHash, err)
			}
			height := receipt.BlockNumber.Uint64()
			if height < nextSideHeight+v.conf.SideConfig.BlocksToWait+1 {
				continue
			}

			for nextSideHeight < height-v.conf.SideConfig.BlocksToWait-1 {
				select {
				case <-ctx.Done():
					v.bdb.Close()
					return
				default:
				}
				log.Infof("handling side height:%d", nextSideHeight)
				endSideHeight := nextSideHeight + batchLength - 1
				if endSideHeight > height-v.conf.SideConfig.BlocksToWait-1 {
					endSideHeight = height - v.conf.SideConfig.BlocksToWait - 1
				}
				lastSideHeight, err := v.fetchLockDepositEvents(nextSideHeight, endSideHeight)
				if err != nil {
					log.Errorf("fetchLockDepositEvents failed:%v", err)
					v.changeEndpoint()
					sleep()
					continue
				}
				nextSideHeight = lastSideHeight
			}

			err = v.bdb.UpdateSideHeight(nextSideHeight)
			if err != nil {
				log.Errorf("UpdateSideHeight failed:%v", err)
			}

		case <-ctx.Done():
			v.bdb.Close()
			log.Info("quiting from signal...")
			return
		}
	}
}

func (v *Voter) getL1FinalizedBatch(ctx context.Context) (uint64, *big.Int, error) {
	result := new(ethtypes.Header)
	err := v.l1clients[v.l1idx].CallContext(context.Background(), result, "eth_getBlockByNumber", "finalized", false)
	if err != nil {
		return 0, nil, fmt.Errorf("l1 GetLastVerifiedBatch failed: %v", err)
	}
	l1Batch, err := v.l1contracts[v.l1idx].GetLastVerifiedBatch(&bind.CallOpts{BlockNumber: result.Number, Context: ctx})
	if err != nil {
		return 0, nil, fmt.Errorf("l1 GetLastVerifiedBatch failed: %v", err)
	}
	return l1Batch, result.Number, nil
}

func (v *Voter) getZkLatestBatchTx(l1Batch, nextL1Batch uint64) (ethcommon.Hash, error) {
	for batch := l1Batch; batch >= nextL1Batch; batch-- {
		rpcBatch, err := v.clients[v.idx].RpcClient.GetBatchByNumber(l1Batch)
		if err != nil {
			return ethcommon.Hash{}, fmt.Errorf("GetBatchByNumber failed: %v", err)
		}
		if len(rpcBatch.Transactions) > 0 {
			return rpcBatch.Transactions[len(rpcBatch.Transactions)-1], nil
		}
	}
	return ethcommon.Hash{}, nil
}

type CrossTransfer struct {
	txIndex string
	txId    []byte
	value   []byte
	toChain uint32
	height  uint64
}

func (v *Voter) fetchLockDepositEventByTxHash(txHash string, l1Batch uint64) error {
	client := v.clients[v.idx]
	contract := v.contracts[v.idx]
	hash := ethcommon.HexToHash(txHash)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reciept, err := client.EthClient.TransactionReceipt(ctx, hash)
	if err != nil {
		return err
	}
	height := reciept.BlockNumber.Uint64()
	batchNumer, err := v.clients[v.idx].RpcClient.BatchNumberByBlockNumber(height)
	if err != nil {
		return fmt.Errorf("txHash: %v BatchNumberByBlockNumber height: %v, err: %v", txHash, height, err)
	}
	if batchNumer > l1Batch {
		log.Infof("txHash: %v, batchNumer: %v, greater than l1Batch: %v", txHash, batchNumer, l1Batch)
		return nil
	}

	for _, l := range reciept.Logs {
		evt, err := contract.ParseCrossChainEvent(*l)
		if err != nil {
			continue
		}
		if l.Address != v.contractAddr {
			log.Errorf("event source contract invalid: %s, expect: %s, txHash: %s", l.Address.Hex(), v.contractAddr.Hex(), txHash)
			continue
		}
		param := &common2.MakeTxParam{}
		_ = param.Deserialization(common.NewZeroCopySource([]byte(evt.Rawdata)))
		if !v.conf.IsWhitelistMethod(param.Method) {
			log.Errorf("target contract method invalid %s, txHash: %s", param.Method, txHash)
			continue
		}

		raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
			append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), param.CrossChainID...))
		if len(raw) != 0 {
			log.Infof("fetchLockDepositEventByTxHash - ccid %s (tx_hash: %s) already on poly",
				hex.EncodeToString(param.CrossChainID), l.TxHash.Hex())
			continue
		}

		index := big.NewInt(0)
		index.SetBytes(evt.TxId)
		crossTx := &CrossTransfer{
			txIndex: encodeBigInt(index),
			txId:    l.TxHash.Bytes(),
			toChain: uint32(evt.ToChainId),
			value:   []byte(evt.Rawdata),
			height:  height,
		}

		_, err = v.commitVote(uint32(height), crossTx.value, crossTx.txId)
		if err != nil {
			log.Errorf("commitVote failed:%v", err)
			continue
		}
	}
	return nil
}

func (v *Voter) fetchLockDepositEvents(startHeight, endHeight uint64) (uint64, error) {
	log.Infof("fetchLockDepositEvents......  start: %v, end: %v", startHeight, endHeight)
	filterContracts := []ethcommon.Address{v.contractAddr}
	topics := [][]ethcommon.Hash{{v.crossChainTopicID}}
	eventLogs, err := v.clients[v.idx].EthClient.FilterLogs(context.Background(), ethereum.FilterQuery{FromBlock: big.NewInt(int64(startHeight)), ToBlock: big.NewInt(int64(endHeight)), Addresses: filterContracts, Topics: topics})
	if err != nil {
		log.Errorf("fetchLockDepositEvents FilterLogs err:%v", err)
		return startHeight, err
	}
	if len(eventLogs) == 0 {
		log.Infof("fetchLockDepositEvents empty start: %v, end: %v", startHeight, endHeight)
		return endHeight + 1, nil
	}
	for _, eventLog := range eventLogs {
		height := eventLog.BlockNumber
		ethTxHash := eventLog.TxHash.String()
		evt, err := v.contracts[v.idx].ParseCrossChainEvent(eventLog)
		if err != nil {
			log.Errorf("fetchLockDepositEvents ParseCrossChainEvent err: %v, height: %v, ethTxHash: %v", err, height, ethTxHash)
			continue
		}
		if eventLog.Address != v.contractAddr {
			log.Errorf("event source contract invalid: %s, expect: %s, height: %d, ethTxHash: %v", eventLog.Address.Hex(), v.contractAddr.Hex(), height, ethTxHash)
			continue
		}
		param := &common2.MakeTxParam{}
		_ = param.Deserialization(common.NewZeroCopySource(evt.Rawdata))
		if !v.conf.IsWhitelistMethod(param.Method) {
			log.Errorf("target contract method invalid %s, height: %d, ethTxHash: %v", param.Method, height, ethTxHash)
			continue
		}

		raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
			append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), param.CrossChainID...))
		if len(raw) != 0 {
			log.Infof("fetchLockDepositEvents - ccid %s (tx_hash: %s) height: %v already on poly",
				hex.EncodeToString(param.CrossChainID), ethTxHash, height)
			continue
		}

		index := big.NewInt(0)
		index.SetBytes(evt.TxId)
		crossTx := &CrossTransfer{
			txIndex: encodeBigInt(index),
			txId:    eventLog.TxHash.Bytes(),
			toChain: uint32(evt.ToChainId),
			value:   evt.Rawdata,
			height:  height,
		}

		var txHash string
		txHash, err = v.commitVote(uint32(height), crossTx.value, crossTx.txId)
		if err != nil {
			log.Errorf("commitVote failed:%v, height: %d, ethTxHash: %v", err, height, ethTxHash)
			return height, err
		}
		err = v.waitTx(txHash)
		if err != nil {
			log.Errorf("waitTx failed:%v,height: %d, ethTxHash: %v", err, height, ethTxHash)
			return height, err
		}
		log.Infof("success side height %d ethTxhash: %v", height, ethTxHash)
	}
	return endHeight + 1, nil
}

func (v *Voter) commitVote(height uint32, value []byte, txhash []byte) (string, error) {
	log.Infof("commitVote, height: %d, value: %s, txhash: %s", height, hex.EncodeToString(value), hex.EncodeToString(txhash))
	tx, err := v.polySdk.Native.Ccm.ImportOuterTransfer(
		v.conf.SideConfig.SideChainId,
		value,
		height,
		nil,
		v.signer.Address[:],
		[]byte{},
		v.signer)
	if err != nil {
		return "", err
	} else {
		log.Infof("commitVote - send transaction to poly chain: ( poly_txhash: %s, eth_txhash: %s, height: %d )",
			tx.ToHexString(), ethcommon.BytesToHash(txhash).String(), height)
		return tx.ToHexString(), nil
	}
}

func (v *Voter) waitTx(txHash string) (err error) {
	start := time.Now()
	var tx *types.Transaction
	for {
		tx, err = v.polySdk.GetTransaction(txHash)
		if tx == nil || err != nil {
			if time.Since(start) > time.Minute*5 {
				err = fmt.Errorf("waitTx timeout")
				return
			}
			time.Sleep(time.Second)
			continue
		}
		return
	}
}

//change endpoint and retry
func (v *Voter) changeEndpoint() {
	v.Lock()
	if v.idx == len(v.clients)-1 {
		v.idx = 0
	} else {
		v.idx = v.idx + 1
	}
	log.Infof("change endpoint to %d", v.idx)
	v.Unlock()
}

func (v *Voter) changeL1Endpoint() {
	v.Lock()
	if v.l1idx == len(v.l1clients)-1 {
		v.l1idx = 0
	} else {
		v.l1idx = v.l1idx + 1
	}
	log.Infof("change l1 endpoint to %d", v.l1idx)
	v.Unlock()
}

func sleep() {
	time.Sleep(time.Second)
}
