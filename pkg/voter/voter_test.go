package voter

import (
	"github.com/polynetwork/side-voter/config"
	"github.com/polynetwork/side-voter/pkg/log"
	"testing"
)

func TestReplenish(t *testing.T) {
	conf := &config.Config{SideConfig: config.SideConfig{
		L1URL:               "https://ethereum-goerli-rpc.allthatnode.com/",
		RestURL:             []string{"https://zksync2-testnet.zksync.dev"},
		L1Contract:          "0x1908e2BF4a88F91E4eF0DC72f02b8Ea36BEa2319",
		ECCMContractAddress: "0xaC2E341cb8E8B04b7a3BD98626626DE3187d8D0B",
		BlocksToWait:        0,
	}, BoltDbPath: "bolt_db"}
	v := New(nil, nil, conf)
	err := v.Init()
	if err != nil {
		t.Fatal(err)
	}
	err = v.fetchLockDepositEventByTxHash("0xd38b3f01ccf0324cc32cadc857e1a20bc62afd11f528f6c892b0db6130975628")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTestNetGetEthL1BatchNumber(t *testing.T) {
	conf := &config.Config{SideConfig: config.SideConfig{
		L1URL:               "https://ethereum-goerli-rpc.allthatnode.com/",
		RestURL:             []string{"https://zksync2-testnet.zksync.dev"},
		L1Contract:          "0x1908e2BF4a88F91E4eF0DC72f02b8Ea36BEa2319",
		ECCMContractAddress: "0xaC2E341cb8E8B04b7a3BD98626626DE3187d8D0B",
		BlocksToWait:        0,
	}, BoltDbPath: "bolt_db"}
	v := New(nil, nil, conf)
	err := v.Init()
	if err != nil {
		t.Fatal(err)
	}
	ethHeight, _, err := ethGetCurrentHeight2(v.conf.SideConfig.L1URL, "finalized")
	if err != nil {
		log.Errorf("get eth height failed:%v", err)
		return
	}
	if ethHeight.Uint64() == 0 {
		log.Errorf("get eth finalized height failed. eth height=%d", ethHeight.Uint64())
		return
	}

	h, err := v.getEthL1BatchNumber(ethHeight.Int64())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(h)
}

func TestMainNetGetEthL1BatchNumber(t *testing.T) {
	conf := &config.Config{SideConfig: config.SideConfig{
		L1URL:               "https://ethereum.publicnode.com",
		RestURL:             []string{"https://zksync2-mainnet.zksync.io"},
		L1Contract:          "0x32400084C286CF3E17e7B677ea9583e60a000324",
		ECCMContractAddress: "0xa0f968eba6bbd08f28dc061c7856c15725983395",
		BlocksToWait:        17,
	}, BoltDbPath: "bolt_db"}
	v := New(nil, nil, conf)
	err := v.Init()
	if err != nil {
		t.Fatal(err)
	}
	ethHeight, _, err := ethGetCurrentHeight2(v.conf.SideConfig.L1URL, "finalized")
	if err != nil {
		log.Errorf("get eth height failed:%v", err)
		return
	}
	if ethHeight.Uint64() == 0 {
		log.Errorf("get eth finalized height failed. eth height=%d", ethHeight.Uint64())
		return
	}

	h, err := v.getEthL1BatchNumber(ethHeight.Int64())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(h)
}
