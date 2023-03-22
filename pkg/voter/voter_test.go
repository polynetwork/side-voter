package voter

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/polynetwork/side-voter/pkg/log"
	"github.com/polynetwork/side-voter/polygon_zk_abi"
	"math/big"
	"testing"
)

func Test_getFinalizedBlockByNumber(t *testing.T) {
	client, _ := rpc.Dial("https://eth-goerli.api.onfinality.io/public")
	result := new(ethtypes.Header)
	err := client.CallContext(context.Background(), result, "eth_getBlockByNumber", "finalized", false)
	if err != nil {
		log.Fatalf("eth_getBlockByNumber failed:%v", err)
	}
	fmt.Println(result.Number)
}

func Test_GetLastVerifiedBatch(t *testing.T) {
	node := "https://eth-goerli.api.onfinality.io/public"
	ethClient, err := ethclient.Dial(node)
	if err != nil {
		log.Fatalf("ethclient.Dial l1 failed:%v", err)
	}
	contract, err := polygon_zk_abi.NewPolygonZkAbiCaller(ethcommon.HexToAddress("0xa997cfD539E703921fD1e3Cf25b4c241a27a4c7A"), ethClient)
	if err != nil {
		log.Fatalf("NewZKEthAbiCaller l1 failed:%v", err)
	}
	fmt.Println(contract.GetLastVerifiedBatch(&bind.CallOpts{BlockNumber: big.NewInt(8686648), Context: context.Background()}))
}
