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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/block-vision/sui-go-sdk/models"
	suisdk "github.com/block-vision/sui-go-sdk/sui"
	"github.com/polynetwork/benfen-voter/config"
	"github.com/polynetwork/benfen-voter/pkg/db"
	"github.com/polynetwork/benfen-voter/pkg/log"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	autils "github.com/polynetwork/poly/native/service/utils"
)

type Voter struct {
	polySdk *sdk.PolySdk
	signer  *sdk.Account
	clients []suisdk.ISuiAPI
	conf    *config.Config
	bdb     *db.BoltDB
	idx     int
	mutex   sync.Mutex
}

func New(polySdk *sdk.PolySdk, signer *sdk.Account, conf *config.Config) *Voter {
	return &Voter{polySdk: polySdk, signer: signer, conf: conf}
}

func (v *Voter) Init() (err error) {
	bdb, err := db.NewBoltDB(v.conf.BoltDbPath)
	if err != nil {
		return
	}

	v.bdb = bdb
	var clients []suisdk.ISuiAPI
	for _, node := range v.conf.SideConfig.RestURL {
		suiSdk := suisdk.NewSuiClient(node)
		clients = append(clients, suiSdk)
	}
	v.clients = clients
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

	ticker := time.NewTicker(time.Second)
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
					err = v.fetchLockDepositEventByTxHash(ctx, txHash.(string))
					if err != nil {
						log.Errorf("fetchLockDepositEventByTxHash failed:%v", err)
						v.changeEndpoint()
						sleep()
						continue
					}
				}
				nextPolyHeight++
			}

		case <-ctx.Done():
			log.Info("quiting from signal...")
			return
		}
	}
}

func (v *Voter) StartVoter(ctx context.Context) {
	cursor := v.bdb.GetSideEventCursor()
	ticker := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-ticker.C:
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				log.Infof("next benfen event cursor:%s", cursor)
				log.CheckRotateLogFile()
				enentsNum, lastDigest, err := v.fetchLockDepositEvents(ctx, cursor)
        
				if err != nil {
					log.Errorf("fetchLockDepositEvents failed:%v", err)
					v.changeEndpoint()
					sleep()
					continue
				}
        
				if enentsNum == 0 {
					break
				}
				log.Infof("benfen lastDigest: %v, nextDigest: %v", lastDigest, cursor)
				if lastDigest != "" && lastDigest != cursor {
					cursor = lastDigest
					err = v.bdb.UpdateSideEventCursor(cursor)
					if err != nil {
						log.Errorf("UpdateSideSequence failed:%v", err)
					}
					if enentsNum == int(v.conf.SideConfig.Batch) {
						continue
					}
				}

				break

			}

		case <-ctx.Done():
			log.Info("quiting from signal...")
			return
		}
	}
}

func (v *Voter) fetchLockDepositEvents(ctx context.Context, cursor string) (int, string, error) {
	eventRequest := models.SuiXQueryEventsRequest{
		SuiEventFilter: models.EventFilterByMoveEventType{
			MoveEventType: v.conf.SideConfig.CcmEventAddress + "::events::CrossChainEvent",
		},
		Limit: v.conf.SideConfig.Batch,
	}
	if cursor != "" {
		eventRequest.Cursor = models.EventId{
			TxDigest: cursor,
			EventSeq: "0",
		}
	}
	events, err := v.clients[v.idx].SuiXQueryEvents(ctx, eventRequest)
	if err != nil {
		log.Errorf("benfen query event failed: %v", err)
		return 0, "", err
	}
	log.Infof("benfen query event start: %v, limit: %v, len(events): %v", cursor, v.conf.SideConfig.Batch, len(events.Data))
	if len(events.Data) == 0 {
		return 0, "", nil
	}

	for _, event := range events.Data {
		cursor = event.Id.TxDigest
		if strings.EqualFold(event.PackageId[3:67], strings.TrimPrefix(v.conf.SideConfig.CcmEventAddress, "0x")) {

			param := &common2.MakeTxParam{}
			raw_data, ok := event.ParsedJson["raw_data"]
			if !ok {
				log.Errorf("no rawdata in event.ParsedJson, digest: %s", event.Id.TxDigest)
				continue
			}
			data, ok := raw_data.([]interface{})
			if !ok {
				log.Errorf("rawdata type error in event.ParsedJson, digest: %s", event.Id.TxDigest)
				continue
			}
			rawData := make([]byte, len(data))
			for i, v := range data {
				rawData[i] = uint8(v.(float64))
			}

			_ = param.Deserialization(common.NewZeroCopySource(rawData))
			if !v.conf.IsWhitelistMethod(param.Method) {
				log.Errorf("target contract method invalid %s, digest: %s", param.Method, event.Id.TxDigest)
				continue
			}

			raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
				append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), param.CrossChainID...))
			if len(raw) != 0 {
				log.Infof("StartVoter - ccid %s (digest: %s) already on poly",
					hex.EncodeToString(param.CrossChainID), event.Id.TxDigest)
				continue
			}

			tx, err := v.clients[v.idx].SuiGetTransactionBlock(ctx, models.SuiGetTransactionBlockRequest{
				Digest: cursor,
				Options: models.SuiTransactionBlockOptions{
					ShowEffects: true,
				},
			})
			if err != nil {
				return len(events.Data), event.Id.TxDigest, err
			}
			//version -> tx, height -> block
			checkpoint, err := strconv.Atoi(tx.Checkpoint)
			if err != nil {
				log.Errorf("tx checkpoint err: %v, digest: %v", err)
				return 0, "", nil
			}

			txHash, err := v.commitVote(uint32(checkpoint), rawData, param.TxHash)
			if err != nil {
				log.Errorf("commitVote failed:%v, txid: %v", err, event.Id.TxDigest)
				return len(events.Data), event.Id.TxDigest, err
			}
			err = v.waitTx(txHash)
			if err != nil {
				log.Errorf("waitTx failed:%v", err)
				return len(events.Data), event.Id.TxDigest, err
			}
		}
	}
	return len(events.Data), cursor, nil
}

func (v *Voter) fetchLockDepositEventByTxHash(ctx context.Context, txHash string) error {
	tx, err := v.clients[v.idx].SuiGetTransactionBlock(ctx, models.SuiGetTransactionBlockRequest{
		Digest: txHash,
		Options: models.SuiTransactionBlockOptions{
			ShowEffects: true,
			ShowEvents:  true,
		},
	})
	if err != nil {
		return fmt.Errorf("fetchLockDepositEventByTxHash, cannot get tx: %s info, err: %s", txHash, err)
	}
	for _, event := range tx.Events {
		if strings.EqualFold(strings.TrimPrefix(event.PackageId, "0x"), strings.TrimPrefix(v.conf.SideConfig.CcmEventAddress, "0x")) {
			param := &common2.MakeTxParam{}
			if event.Type != v.conf.SideConfig.CcmEventAddress+"::events::CrossChainEvent" {
				continue
			}
			raw_data, ok := event.ParsedJson["raw_data"]
			if !ok {
				log.Errorf("no rawdata in event.ParsedJson, digest: %s", event.Id.TxDigest)
				continue
			}
			data, ok := raw_data.([]interface{})
			if !ok {
				log.Errorf("rawdata type error in event.ParsedJson, digest: %s", event.Id.TxDigest)
				continue
			}
			rawData := make([]byte, len(data))
			for i, v := range data {
				rawData[i] = uint8(v.(float64))
			}

			_ = param.Deserialization(common.NewZeroCopySource(rawData))
			if !v.conf.IsWhitelistMethod(param.Method) {
				log.Errorf("target contract method invalid %s, txHash: %s", param.Method, txHash)
				continue
			}

			raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
				append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), param.CrossChainID...))
			if len(raw) != 0 {
				log.Infof("fetchLockDepositEventByTxHash - ccid %s (tx_hash: %s) already on poly",
					hex.EncodeToString(param.CrossChainID), txHash)
				continue
			}

			//version -> tx, height -> block
			checkpoint, err := strconv.Atoi(tx.Checkpoint)
			if err != nil {
				log.Errorf("tx checkpoint err: %v, txHash: %s", err, txHash)
				continue
			}
			txHash, err = v.commitVote(uint32(checkpoint), rawData, param.TxHash)
			if err != nil {
				log.Errorf("commitVote failed:%v", err)
				continue
			}
		}
	}

	return nil
}

func (v *Voter) commitVote(checkpoint uint32, value []byte, txid []byte) (string, error) {
	log.Infof("commitVote, checkpoint: %d, value: %s, txid: %s", checkpoint, hex.EncodeToString(value), hex.EncodeToString(txid))
	tx, err := v.polySdk.Native.Ccm.ImportOuterTransfer(
		v.conf.SideConfig.SideChainId,
		value,
		checkpoint,
		nil,
		v.signer.Address[:],
		[]byte{},
		v.signer)
	if err != nil {
		return "", err
	} else {
		log.Infof("commitVote - send transaction to poly chain: ( poly_txhash: %s, side_txid: %s, side_version: %d )",
			tx.ToHexString(), hex.EncodeToString(txid), checkpoint)
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

func sleep() {
	time.Sleep(time.Second)
}

func (v *Voter) changeEndpoint() {
	v.mutex.Lock()
	defer func() {
		v.mutex.Unlock()
	}()

	if v.idx == len(v.clients)-1 {
		v.idx = 0
	} else {
		v.idx = v.idx + 1
	}
	log.Infof("change endpoint to %d", v.idx)
}
