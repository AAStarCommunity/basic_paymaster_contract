// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "account-abstraction/contracts/core/UserOperationLib.sol";
import {BasePaymaster} from "account-abstraction/contracts/core/BasePaymaster.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import "account-abstraction/contracts/core/Helpers.sol" as Helpers;

/**
 * A paymaster based on the eth-infinitism sample VerifyingPaymaster contract.
 * It has the same functionality as the sample, but with added support for withdrawing ERC20 tokens.
 * All withdrawn tokens will be transferred to the owner address.
 * Note that the off-chain signer should have a strategy in place to handle a failed token withdrawal.
 *
 * See account-abstraction/contracts/samples/VerifyingPaymaster.sol for detailed comments.
 */
contract VerifyingPaymaster is BasePaymaster {
    using ECDSA for bytes32;
    using UserOperationLib for PackedUserOperation;
    using SafeERC20 for IERC20;

    uint256 private constant VALID_PND_OFFSET = 52;

    uint256 private constant SIGNATURE_OFFSET = 180;

    uint256 public constant POST_OP_GAS = 35000;

    address public verifier;

    address public vault;

    constructor(IEntryPoint _entryPoint, address _owner) BasePaymaster(_entryPoint) {
        _transferOwnership(_owner);
        verifier = _owner;
        vault = _owner;
    }

    function setVerifier(address _verifier) public onlyOwner {
        verifier = _verifier;
    }

    function setVault(address _vault) public onlyOwner {
        vault = _vault;
    }

    function pack(PackedUserOperation calldata userOp) internal pure returns (bytes memory ret) {
        return
            abi.encode(
            userOp.getSender(),
            userOp.nonce,
            Helpers.calldataKeccak(userOp.initCode),
            Helpers.calldataKeccak(userOp.callData),
            userOp.accountGasLimits,
            userOp.preVerificationGas,
            userOp.gasFees
        );
    }

    function getHash(
        PackedUserOperation calldata userOp,
        uint48 validUntil,
        uint48 validAfter,
        address erc20Token,
        uint256 exchangeRate
    ) public view returns (bytes32) {
        return
            keccak256(
            abi.encode(pack(userOp), block.chainid, address(this), validUntil, validAfter, erc20Token, exchangeRate)
        );
    }

    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /*userOpHash*/,
        uint256 maxCost
    ) internal view override returns (bytes memory context, uint256 validationData) {
        (maxCost);
        (
            uint48 validUntil,
            uint48 validAfter,
            address erc20Token,
            uint256 exchangeRate,
            bytes calldata signature
        ) = parsePaymasterAndData(userOp.paymasterAndData);
        // solhint-disable-next-line reason-string
        require(
            signature.length == 64 || signature.length == 65,
            "VerifyingPaymaster: invalid signature length in paymasterAndData"
        );
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter, erc20Token, exchangeRate));
        context = "";
        if (erc20Token != address(0)) {
            context = abi.encode(
                userOp.sender,
                erc20Token,
                exchangeRate,
                userOp.gasFees
            );
        }

        if (verifier != ECDSA.recover(hash, signature)) {
            return (context, Helpers._packValidationData(true, validUntil, validAfter));
        }

        return (context, Helpers._packValidationData(false, validUntil, validAfter));
    }

    function _postOp(PostOpMode mode, bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas) internal override {
        (address sender, IERC20 token, uint256 exchangeRate, bytes32 gasFee) = abi
            .decode(context, (address, IERC20, uint256, bytes32));
        (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) = UserOperationLib.unpackUints(gasFee);

        uint256 opGasPrice;
        unchecked {
            if (maxFeePerGas == maxPriorityFeePerGas) {
                opGasPrice = maxFeePerGas;
            } else {
                opGasPrice = Math.min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
            }
        }

        uint256 actualTokenCost = ((actualGasCost + (POST_OP_GAS * actualUserOpFeePerGas)) * exchangeRate) / 1e18;
        if (mode != PostOpMode.postOpReverted) {
            token.safeTransferFrom(sender, vault, actualTokenCost);
        }
    }

    function parsePaymasterAndData(
        bytes calldata paymasterAndData
    )
    public
    pure
    returns (
        uint48 validUntil,
        uint48 validAfter,
        address erc20Token,
        uint256 exchangeRate,
        bytes calldata signature
    )
    {
        (validUntil, validAfter, erc20Token, exchangeRate) = abi.decode(
            paymasterAndData[VALID_PND_OFFSET : SIGNATURE_OFFSET],
            (uint48, uint48, address, uint256)
        );
        signature = paymasterAndData[SIGNATURE_OFFSET :];
    }
}
