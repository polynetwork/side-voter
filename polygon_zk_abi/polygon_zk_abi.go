// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package polygon_zk_abi

import (
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// PolygonZkAbiABI is the input ABI used to generate the binding from.
const PolygonZkAbiABI = "[{\"inputs\":[],\"name\":\"getLastVerifiedBatch\",\"outputs\":[{\"internalType\":\"uint64\",\"name\":\"\",\"type\":\"uint64\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"

// PolygonZkAbi is an auto generated Go binding around an Ethereum contract.
type PolygonZkAbi struct {
	PolygonZkAbiCaller     // Read-only binding to the contract
	PolygonZkAbiTransactor // Write-only binding to the contract
	PolygonZkAbiFilterer   // Log filterer for contract events
}

// PolygonZkAbiCaller is an auto generated read-only Go binding around an Ethereum contract.
type PolygonZkAbiCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PolygonZkAbiTransactor is an auto generated write-only Go binding around an Ethereum contract.
type PolygonZkAbiTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PolygonZkAbiFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type PolygonZkAbiFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PolygonZkAbiSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type PolygonZkAbiSession struct {
	Contract     *PolygonZkAbi     // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// PolygonZkAbiCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type PolygonZkAbiCallerSession struct {
	Contract *PolygonZkAbiCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts       // Call options to use throughout this session
}

// PolygonZkAbiTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type PolygonZkAbiTransactorSession struct {
	Contract     *PolygonZkAbiTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts       // Transaction auth options to use throughout this session
}

// PolygonZkAbiRaw is an auto generated low-level Go binding around an Ethereum contract.
type PolygonZkAbiRaw struct {
	Contract *PolygonZkAbi // Generic contract binding to access the raw methods on
}

// PolygonZkAbiCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type PolygonZkAbiCallerRaw struct {
	Contract *PolygonZkAbiCaller // Generic read-only contract binding to access the raw methods on
}

// PolygonZkAbiTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type PolygonZkAbiTransactorRaw struct {
	Contract *PolygonZkAbiTransactor // Generic write-only contract binding to access the raw methods on
}

// NewPolygonZkAbi creates a new instance of PolygonZkAbi, bound to a specific deployed contract.
func NewPolygonZkAbi(address common.Address, backend bind.ContractBackend) (*PolygonZkAbi, error) {
	contract, err := bindPolygonZkAbi(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &PolygonZkAbi{PolygonZkAbiCaller: PolygonZkAbiCaller{contract: contract}, PolygonZkAbiTransactor: PolygonZkAbiTransactor{contract: contract}, PolygonZkAbiFilterer: PolygonZkAbiFilterer{contract: contract}}, nil
}

// NewPolygonZkAbiCaller creates a new read-only instance of PolygonZkAbi, bound to a specific deployed contract.
func NewPolygonZkAbiCaller(address common.Address, caller bind.ContractCaller) (*PolygonZkAbiCaller, error) {
	contract, err := bindPolygonZkAbi(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &PolygonZkAbiCaller{contract: contract}, nil
}

// NewPolygonZkAbiTransactor creates a new write-only instance of PolygonZkAbi, bound to a specific deployed contract.
func NewPolygonZkAbiTransactor(address common.Address, transactor bind.ContractTransactor) (*PolygonZkAbiTransactor, error) {
	contract, err := bindPolygonZkAbi(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &PolygonZkAbiTransactor{contract: contract}, nil
}

// NewPolygonZkAbiFilterer creates a new log filterer instance of PolygonZkAbi, bound to a specific deployed contract.
func NewPolygonZkAbiFilterer(address common.Address, filterer bind.ContractFilterer) (*PolygonZkAbiFilterer, error) {
	contract, err := bindPolygonZkAbi(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &PolygonZkAbiFilterer{contract: contract}, nil
}

// bindPolygonZkAbi binds a generic wrapper to an already deployed contract.
func bindPolygonZkAbi(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(PolygonZkAbiABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_PolygonZkAbi *PolygonZkAbiRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _PolygonZkAbi.Contract.PolygonZkAbiCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_PolygonZkAbi *PolygonZkAbiRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _PolygonZkAbi.Contract.PolygonZkAbiTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_PolygonZkAbi *PolygonZkAbiRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _PolygonZkAbi.Contract.PolygonZkAbiTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_PolygonZkAbi *PolygonZkAbiCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _PolygonZkAbi.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_PolygonZkAbi *PolygonZkAbiTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _PolygonZkAbi.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_PolygonZkAbi *PolygonZkAbiTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _PolygonZkAbi.Contract.contract.Transact(opts, method, params...)
}

// GetLastVerifiedBatch is a free data retrieval call binding the contract method 0xc0ed84e0.
//
// Solidity: function getLastVerifiedBatch() view returns(uint64)
func (_PolygonZkAbi *PolygonZkAbiCaller) GetLastVerifiedBatch(opts *bind.CallOpts) (uint64, error) {
	var (
		ret0 = new(uint64)
	)
	out := ret0
	err := _PolygonZkAbi.contract.Call(opts, out, "getLastVerifiedBatch")
	return *ret0, err
}

// GetLastVerifiedBatch is a free data retrieval call binding the contract method 0xc0ed84e0.
//
// Solidity: function getLastVerifiedBatch() view returns(uint64)
func (_PolygonZkAbi *PolygonZkAbiSession) GetLastVerifiedBatch() (uint64, error) {
	return _PolygonZkAbi.Contract.GetLastVerifiedBatch(&_PolygonZkAbi.CallOpts)
}

// GetLastVerifiedBatch is a free data retrieval call binding the contract method 0xc0ed84e0.
//
// Solidity: function getLastVerifiedBatch() view returns(uint64)
func (_PolygonZkAbi *PolygonZkAbiCallerSession) GetLastVerifiedBatch() (uint64, error) {
	return _PolygonZkAbi.Contract.GetLastVerifiedBatch(&_PolygonZkAbi.CallOpts)
}
