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

type headerRep struct {
	JSONRPC string `json:"jsonrpc"`
	Result  *struct {
		Number string
	}
	ID uint `json:"id"`
}

func ethGetCurrentHeight(url string, finalized bool) (height uint64, err error) {
	if finalized {
		return ethGetBlockByNumberFinalized(url)
	}
	return ethBlockNumber(url)
}

func ethBlockNumber(url string) (height uint64, err error) {
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

func ethGetBlockByNumberFinalized(url string) (number uint64, err error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getBlockByNumber",
		"params":  []interface{}{"finalized", false},
		"id":      1,
	}
	data, _ := json.Marshal(req)
	body, err := jsonRequest(url, data)
	if err != nil {
		return
	}

	var resp headerRep
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return
	}
	if resp.Result == nil || resp.Result.Number == "" {
		err = fmt.Errorf("invalid response %s", string(body))
		return
	}

	h, ok := new(big.Int).SetString(strings.TrimPrefix(resp.Result.Number, "0x"), 16)
	if !ok {
		err = fmt.Errorf("invalid block number")
		return
	}
	number = h.Uint64()
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
