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
	"github.com/polynetwork/poly/core/types"
	"math/big"
	"strings"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/eth-contracts/go_abi/eccm_abi"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	autils "github.com/polynetwork/poly/native/service/utils"
	"github.com/polynetwork/side-voter/config"
	"github.com/polynetwork/side-voter/pkg/db"
	"github.com/polynetwork/side-voter/pkg/log"
)

type Voter struct {
	polySdk           *sdk.PolySdk
	signer            *sdk.Account
	conf              *config.Config
	clients           []*ethclient.Client
	bdb               *db.BoltDB
	contracts         []*eccm_abi.EthCrossChainManager
	contractAddr      ethcommon.Address
	crossChainTopicID ethcommon.Hash
	idx               int
}

func New(polySdk *sdk.PolySdk, signer *sdk.Account, conf *config.Config) *Voter {
	return &Voter{polySdk: polySdk, signer: signer, conf: conf}
}

func (v *Voter) Init() (err error) {
	var clients []*ethclient.Client
	for _, node := range v.conf.SideConfig.RestURL {
		client, err := ethclient.Dial(node)
		if err != nil {
			log.Fatalf("ethclient.Dial failed:%v", err)
		}

		clients = append(clients, client)
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
		contract, err := eccm_abi.NewEthCrossChainManager(v.contractAddr, v.clients[i])
		if err != nil {
			return err
		}
		v.contracts[i] = contract
	}

	return
}

func (v *Voter) StartReplenish(ctx context.Context) {
	var nextPolyHeight uint64
	if v.conf.ForceConfig.PolyHeight != 0 {
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

				for _, txHash := range txHashList {
					err = v.fetchLockDepositEventByTxHash(txHash.(string))
					if err != nil {
						log.Errorf("fetchLockDepositEventByTxHash failed:%v", err)
						//change endpoint and retry, mutex is not used
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
	var batchLength uint64 = 1
	if v.conf.SideConfig.Batch > 0 {
		batchLength = v.conf.SideConfig.Batch
	}
	ticker := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-ticker.C:
			height, err := ethGetCurrentHeight(v.conf.SideConfig.RestURL[v.idx], v.conf.SideConfig.Finalized)
			if err != nil {
				log.Errorf("ethGetCurrentHeight failed:%v", err)
				v.changeEndpoint()
				continue
			}
			log.Infof("current side height:%d", height)
			if height < nextSideHeight+v.conf.SideConfig.BlocksToWait+1 {
				continue
			}

			if v.conf.SideConfig.TimeToWait > 0 {
				time.Sleep(time.Second * time.Duration(v.conf.SideConfig.TimeToWait))
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

type CrossTransfer struct {
	txIndex string
	txId    []byte
	value   []byte
	toChain uint32
	height  uint64
}

func (v *Voter) fetchLockDepositEventByTxHash(txHash string) error {
	client := v.clients[v.idx]
	contract := v.contracts[v.idx]
	hash := ethcommon.HexToHash(txHash)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reciept, err := client.TransactionReceipt(ctx, hash)
	if err != nil {
		return err
	}
	height := reciept.BlockNumber.Uint64()
	latestHeight, err := ethGetCurrentHeight(v.conf.SideConfig.RestURL[v.idx], v.conf.SideConfig.Finalized)
	if err != nil {
		return err
	}
	if height+v.conf.SideConfig.BlocksToWait > latestHeight {
		return fmt.Errorf("transaction is not confirmed yet %s", txHash)
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

		txHash, err = v.commitVote(uint32(height), crossTx.value, crossTx.txId)
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
	eventLogs, err := v.clients[v.idx].FilterLogs(context.Background(), ethereum.FilterQuery{FromBlock: big.NewInt(int64(startHeight)), ToBlock: big.NewInt(int64(endHeight)), Addresses: filterContracts, Topics: topics})
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
		_ = param.Deserialization(common.NewZeroCopySource([]byte(evt.Rawdata)))
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
			value:   []byte(evt.Rawdata),
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

//change endpoint and retry, mutex is not used
func (v *Voter) changeEndpoint() {
	if v.idx == len(v.clients)-1 {
		v.idx = 0
	} else {
		v.idx = v.idx + 1
	}
	log.Infof("change endpoint to %d", v.idx)
}

func sleep() {
	time.Sleep(time.Second)
}
