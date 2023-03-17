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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/polynetwork/side-voter/pkg/log"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
)

type heightReq struct {
	JSONRPC string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
	ID      uint     `json:"id"`
}

type heightRep struct {
	JSONRPC string `json:"jsonrpc"`
	Result  string `json:"result"`
	ID      uint   `json:"id"`
}

type HeaderRep struct {
	JSONRPC string `json:"jsonrpc"`
	Result  *struct {
		Number          string
		L1BatchNumber   string
		TotalDifficulty string
	}
	ID uint `json:"id"`
}

func ethGetCurrentHeight2(url string, param string) (number, diff *big.Int, err error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getBlockByNumber",
		"params":  []interface{}{param, false},
		"id":      1,
	}
	data, _ := json.Marshal(req)
	body, err := jsonRequest(url, data)
	if err != nil {
		return
	}

	var resp HeaderRep
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return
	}
	if resp.Result == nil || resp.Result.Number == "" {
		err = fmt.Errorf("invalid response %s", string(body))
		return
	}
	number, ok := new(big.Int).SetString(strings.TrimPrefix(resp.Result.Number, "0x"), 16)
	if !ok {
		err = fmt.Errorf("invalid block number")
		return
	}
	diff, ok = new(big.Int).SetString(strings.TrimPrefix(resp.Result.TotalDifficulty, "0x"), 16)
	if !ok {
		err = fmt.Errorf("invalid block total difficulty")
		return
	}
	return
}

func getZkL1BatchNumber(url string, height uint64) (l1BatchNumber *big.Int, err error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getBlockByNumber",
		"params":  []interface{}{strconv.FormatUint(height, 16), false},
		"id":      1,
	}
	data, _ := json.Marshal(req)
	body, err := jsonRequest(url, data)
	if err != nil {
		return
	}

	var resp HeaderRep
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return
	}
	if resp.Result == nil {
		err = fmt.Errorf("invalid response %s", string(body))
		return
	}

	if resp.Result.L1BatchNumber == "" {
		return new(big.Int), nil
	}

	l1BatchNumber, ok := new(big.Int).SetString(strings.TrimPrefix(resp.Result.L1BatchNumber, "0x"), 16)
	if !ok {
		err = fmt.Errorf("invalid L1BatchNumber")
		return
	}

	return
}

func getZkL1LatestConfirmedHeight(url string, nextHeight uint64, ethL1BatchNum uint64) (confirmedHeight uint64, err error) {
	confirmedHeight = nextHeight
	for {
		zkL1BatchNumber, err := getZkL1BatchNumber(url, confirmedHeight)
		if err != nil {
			log.Errorf("getZkL1BatchNumber failed. height:%d, err:%v", confirmedHeight, err)
			return confirmedHeight - 1, nil
		}
		if zkL1BatchNumber.Uint64() == 0 {
			break
		}

		if zkL1BatchNumber.Uint64() > ethL1BatchNum {
			break
		}
		log.Infof("zk height %d confirmed on L1 ", confirmedHeight)

		confirmedHeight++
	}

	return confirmedHeight - 1, nil

}

func ethGetCurrentHeight(url string) (height uint64, err error) {
	req := &heightReq{
		JSONRPC: "2.0",
		Method:  "eth_blockNumber",
		Params:  make([]string, 0),
		ID:      1,
	}
	data, _ := json.Marshal(req)

	body, err := jsonRequest(url, data)
	if err != nil {
		return
	}

	var resp heightRep
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return
	}

	height, err = strconv.ParseUint(resp.Result, 0, 64)
	if err != nil {
		return
	}

	return
}

func encodeBigInt(b *big.Int) string {
	if b.Uint64() == 0 {
		return "00"
	}
	return hex.EncodeToString(b.Bytes())
}

func jsonRequest(url string, data []byte) (result []byte, err error) {
	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return
	}

	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}
