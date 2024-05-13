import { ethers } from 'hardhat'
import { expect } from 'chai'

import {
  EntryPoint, EntryPointSimulations, EntryPointSimulations__factory,
  SimpleAccount,
  SimpleAccountFactory,
  SimpleAccountFactory__factory,
  SimpleAccount__factory,
  TestCounter__factory,
  VerifyingPaymaster,
  VerifyingPaymaster__factory,
} from 'accountabstraction/typechain'
import {
  ONE_ETH,
  createAccount,
  createAccountOwner,
  createAddress,
  fund,
  getAccountAddress,
  getAccountInitCode,
  getBalance, deployEntryPoint, decodeRevertReason, findSimulationUserOpWithMin, findUserOpWithMin
} from 'accountabstraction/test/testutils'

import { fillAndSign, fillSignAndPack, packUserOp, simulateHandleOp, simulateValidation, signPackedUserOp } from 'accountabstraction/test/UserOp'
import { BigNumber, Wallet } from 'ethers'
import { hexConcat, parseEther } from 'ethers/lib/utils'
import { PackedUserOperation, UserOperation } from 'accountabstraction/test/UserOperation'
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

import { deployVerifyingPaymasterFixture } from "./VerifyingPaymaster.fixture";

const provider = ethers.provider
describe('EntryPointSimulations', function () {
  const ethersSigner = ethers.provider.getSigner()

  let account: SimpleAccount
  let accountOwner: Wallet
  let simpleAccountFactory: SimpleAccountFactory

  let entryPoint: EntryPoint
  let epSimulation: EntryPointSimulations

  before(async function () {
    entryPoint = await deployEntryPoint()
    epSimulation = await new EntryPointSimulations__factory(provider.getSigner()).deploy()

    accountOwner = createAccountOwner();
    ({
      proxy: account,
      accountFactory: simpleAccountFactory
    } = await createAccount(ethersSigner, await accountOwner.getAddress(), entryPoint.address))

    // await checkStateDiffSupported()
  })

  /*
  describe('Simulation Contract Sanity checks', () => {
    // validate that successful simulation is always successful on real entrypoint,
    // regardless of "environment" parameters (like gaslimit)
    const addr = createAddress()

    // coverage skews gas checks.
    if (process.env.COVERAGE != null) {
      return
    }

    function costInRange (simCost: BigNumber, epCost: BigNumber, message: string): void {
      const diff = simCost.sub(epCost).toNumber()
      const max = 350
      expect(diff).to.be.within(0, max,
        `${message} cost ${simCost.toNumber()} should be (up to ${max}) above ep cost ${epCost.toNumber()}`)
    }
    it('deposit on simulation must be >= real entrypoint', async () => {
      costInRange(
        await epSimulation.estimateGas.depositTo(addr, { value: 1 }),
        await entryPoint.estimateGas.depositTo(addr, { value: 1 }), 'deposit with value')
    })
    it('deposit without value on simulation must be >= real entrypoint', async () => {
      costInRange(
        await epSimulation.estimateGas.depositTo(addr, { value: 0 }),
        await entryPoint.estimateGas.depositTo(addr, { value: 0 }), 'deposit without value')
    })
    it('eth transfer on simulation must be >= real entrypoint', async () => {
      costInRange(
        await provider.estimateGas({ to: epSimulation.address, value: 1 }),
        await provider.estimateGas({ to: entryPoint.address, value: 1 }), 'eth transfer with value')
    })
    it('eth transfer (even without value) on simulation must be >= real entrypoint', async () => {
      costInRange(
        await provider.estimateGas({ to: epSimulation.address, value: 0 }),
        await provider.estimateGas({ to: entryPoint.address, value: 0 }), 'eth transfer with value')
    })
  })
  
  //async function checkStateDiffSupported (): Promise<void> {
  //  const tx: TransactionRequest = {
  //    to: entryPoint.address,
  //    data: '0x'
  //  }
  //  const stateOverride = {
  //    [entryPoint.address]: {
  //      code: '0x61030960005260206000f3'
  //      // 0000  61  PUSH2 0x0309  | value  777
  //      // 0003  60  PUSH1 0x00    | offset   0
  //      // 0005  52  MSTORE        |
  //      // 0006  60  PUSH1 0x20    | size    32
  //      // 0008  60  PUSH1 0x00    | offset   0
  //      // 000A  F3  RETURN        |
  //    }
  //  }
  //  const simulationResult = await ethers.provider.send('eth_call', [tx, 'latest', stateOverride])
  //  expect(parseInt(simulationResult, 16)).to.equal(777)
  //}


  describe('#simulateValidation', () => {
    const accountOwner1 = createAccountOwner()
    let account1: SimpleAccount

    before(async () => {
      ({ proxy: account1 } = await createAccount(ethersSigner, await accountOwner1.getAddress(), entryPoint.address))
      await account.addDeposit({ value: ONE_ETH })
      expect(await getBalance(account.address)).to.equal(0)
      expect(await account.getDeposit()).to.eql(ONE_ETH)
    })

    it('should fail if validateUserOp fails', async () => {
      // using wrong nonce
      const op = await fillSignAndPack({ sender: account.address, nonce: 1234 }, accountOwner, entryPoint)
      //await expect(simulateValidation(op, entryPoint.address)).to
      //  .revertedWith('AA25 invalid account nonce')
      expect(await simulateValidation(op, entryPoint.address).catch(e => console.log(decodeRevertReason(e))));
    })

    it('should report signature failure without revert', async () => {
      // (this is actually a feature of the wallet, not the entrypoint)
      // using wrong owner for account1
      // (zero gas price so that it doesn't fail on prefund)
      const op = await fillSignAndPack({ sender: account1.address, maxFeePerGas: 0 }, accountOwner, entryPoint)
      const { returnInfo } = await simulateValidation(op, entryPoint.address)
      expect(returnInfo.accountValidationData).to.equal(1)
    })

    it('should revert if wallet not deployed (and no initCode)', async () => {
      const op = await fillSignAndPack({
        sender: createAddress(),
        nonce: 0,
        verificationGasLimit: 1000
      }, accountOwner, entryPoint)
      await expect(simulateValidation(op, entryPoint.address)).to
        .revertedWith('AA20 account not deployed')
    })

    it('should revert on oog if not enough verificationGas', async () => {
      const op = await fillSignAndPack({ sender: account.address, verificationGasLimit: 1000 }, accountOwner, entryPoint)
      //await expect(simulateValidation(op, entryPoint.address)).to
      //  .revertedWith('AA23 reverted')
      expect(await simulateValidation(op, entryPoint.address).catch(e => console.log(decodeRevertReason(e))));
    })

    it('should succeed if validateUserOp succeeds', async () => {
      const op = await fillSignAndPack({ sender: account1.address }, accountOwner1, entryPoint)
      await fund(account1)
      await simulateValidation(op, entryPoint.address)
    })

    it('should return empty context if no paymaster', async () => {
      const op = await fillSignAndPack({ sender: account1.address, maxFeePerGas: 0 }, accountOwner1, entryPoint)
      const { returnInfo } = await simulateValidation(op, entryPoint.address)
      expect(returnInfo.paymasterContext).to.eql('0x')
    })

    it('should return stake of sender', async () => {
      const stakeValue = BigNumber.from(123)
      const unstakeDelay = 3
      const { proxy: account2 } = await createAccount(ethersSigner, await ethersSigner.getAddress(), entryPoint.address)
      await fund(account2)
      await account2.execute(entryPoint.address, stakeValue, entryPoint.interface.encodeFunctionData('addStake', [unstakeDelay]))
      const op = await fillSignAndPack({ sender: account2.address }, ethersSigner, entryPoint)
      const result = await simulateValidation(op, entryPoint.address)
      expect(result.senderInfo.stake).to.equal(stakeValue)
      expect(result.senderInfo.unstakeDelaySec).to.equal(unstakeDelay)
    })

    it('should prevent overflows: fail if any numeric value is more than 120 bits', async () => {
      const op = await fillSignAndPack({
        preVerificationGas: BigNumber.from(2).pow(130),
        sender: account1.address
      }, accountOwner1, entryPoint)
      await expect(
        simulateValidation(op, entryPoint.address)
      ).to.revertedWith('gas values overflow')
    })

    it('should fail creation for wrong sender', async () => {
      const op1 = await fillSignAndPack({
        initCode: getAccountInitCode(accountOwner1.address, simpleAccountFactory),
        sender: '0x'.padEnd(42, '1'),
        verificationGasLimit: 30e6
      }, accountOwner1, entryPoint)
      await expect(simulateValidation(op1, entryPoint.address))
        .to.revertedWith('AA14 initCode must return sender')
    })

    it('should report failure on insufficient verificationGas (OOG) for creation', async () => {
      const initCode = getAccountInitCode(accountOwner1.address, simpleAccountFactory)
      const sender = await entryPoint.callStatic.getSenderAddress(initCode).catch(e => e.errorArgs.sender)
      const op0 = await fillSignAndPack({
        initCode,
        sender,
        verificationGasLimit: 5e5,
        maxFeePerGas: 0
      }, accountOwner1, entryPoint)
      // must succeed with enough verification gas.
      await simulateValidation(op0, entryPoint.address, { gas: '0xF4240' })

      const op1 = await fillSignAndPack({
        initCode,
        sender,
        verificationGasLimit: 1e5,
        maxFeePerGas: 0
      }, accountOwner1, entryPoint)
      await expect(simulateValidation(op1, entryPoint.address, { gas: '0xF4240' }))
        .to.revertedWith('AA13 initCode failed or OOG')
    })

    it('should succeed for creating an account', async () => {
      const sender = await getAccountAddress(accountOwner1.address, simpleAccountFactory)
      const op1 = await fillSignAndPack({
        sender,
        initCode: getAccountInitCode(accountOwner1.address, simpleAccountFactory)
      }, accountOwner1, entryPoint)
      await fund(op1.sender)

      await simulateValidation(op1, entryPoint.address)
    })

    it('should not call initCode from entrypoint', async () => {
      // a possible attack: call an account's execFromEntryPoint through initCode. This might lead to stolen funds.
      const { proxy: account } = await createAccount(ethersSigner, await accountOwner.getAddress(), entryPoint.address)
      const sender = createAddress()
      const op1 = await fillSignAndPack({
        initCode: hexConcat([
          account.address,
          account.interface.encodeFunctionData('execute', [sender, 0, '0x'])
        ]),
        sender
      }, accountOwner, entryPoint)
      const error = await simulateValidation(op1, entryPoint.address).catch(e => e)
      expect(error.message).to.match(/initCode failed or OOG/, error)
    })
  })

  describe('over-validation test', () => {
    // coverage skews gas checks.
    if (process.env.COVERAGE != null) {
      return
    }

    let vgl: number
    let pmVgl: number
    let paymaster: VerifyingPaymaster
    let sender: string
    let owner: Wallet
    async function userOpWithGas (vgl: number, pmVgl = 0): Promise<UserOperation> {
      return fillAndSign({
        sender,
        verificationGasLimit: vgl,
        paymaster: pmVgl !== 0 ? paymaster.address : undefined,
        paymasterVerificationGasLimit: pmVgl,
        paymasterPostOpGasLimit: pmVgl,
        maxFeePerGas: 1,
        maxPriorityFeePerGas: 1
      }, owner, entryPoint)
    }
    before(async () => {
      owner = createAccountOwner()
      paymaster = await new VerifyingPaymaster__factory(ethersSigner).deploy(entryPoint.address)
      await entryPoint.depositTo(paymaster.address, { value: parseEther('1') })
      const { proxy: account } = await createAccount(ethersSigner, owner.address, entryPoint.address)
      sender = account.address
      await fund(account)
      pmVgl = await findSimulationUserOpWithMin(async n => userOpWithGas(1e6, n), entryPoint, 1, 500000)
      vgl = await findSimulationUserOpWithMin(async n => userOpWithGas(n, pmVgl), entryPoint, 3000, 500000)

      const userOp = await userOpWithGas(vgl, pmVgl)

      await simulateValidation(packUserOp(userOp), entryPoint.address)
        .catch(e => { throw new Error(decodeRevertReason(e)!) })
    })
    describe('compare to execution', () => {
      let execVgl: number
      let execPmVgl: number
      const diff = 2000
      before(async () => {
        execPmVgl = await findUserOpWithMin(async n => userOpWithGas(1e6, n), false, entryPoint, 1, 500000)
        execVgl = await findUserOpWithMin(async n => userOpWithGas(n, execPmVgl), false, entryPoint, 1, 500000)
      })
      it('account verification simulation cost should be higher than execution', function () {
        console.log('simulation account validation', vgl, 'above exec:', vgl - execVgl)
        expect(vgl).to.be.within(execVgl + 1, execVgl + diff, `expected simulation verificationGas to be 1..${diff} above actual, but was ${vgl - execVgl}`)
      })
      it('paymaster verification simulation cost should be higher than execution', function () {
        console.log('simulation paymaster validation', pmVgl, 'above exec:', pmVgl - execPmVgl)
        expect(pmVgl).to.be.within(execPmVgl + 1, execPmVgl + diff, `expected simulation verificationGas to be 1..${diff} above actual, but was ${pmVgl - execPmVgl}`)
      })
    })
    it('should revert with AA2x if verificationGasLimit is low', async function () {
      expect(await simulateValidation(packUserOp(await userOpWithGas(vgl - 1, pmVgl)), entryPoint.address)
        .catch(decodeRevertReason))
        .to.match(/AA26/)
    })
    it('should revert with AA3x if paymasterVerificationGasLimit is low', async function () {
      expect(await simulateValidation(packUserOp(await userOpWithGas(vgl, pmVgl - 1)), entryPoint.address)
        .catch(decodeRevertReason))
        .to.match(/AA36/)
    })
  })
  */

  describe('#simulateHandleOp', () => {
    const MOCK_VALID_UNTIL = "0x00000000deadbeef";
    const MOCK_VALID_AFTER = "0x0000000000001234";
    const MOCK_SIG = "0x1234";
    const MOCK_ERC20_ADDR = "0x" + "01".repeat(20);
    // Assume TOKEN decimals is 18, then 1 ETH = 1000 TOKENS
    const MOCK_FX = ethers.constants.WeiPerEther.mul(1000);
    const encodePaymasterData = (token = ethers.constants.AddressZero, fx = ethers.constants.Zero) => {
      return ethers.utils.defaultAbiCoder.encode(
        ["uint48", "uint48", "address", "uint256"],
        [MOCK_VALID_UNTIL, MOCK_VALID_AFTER, token, fx],
      );
    };
    
    it('should simulate creation', async () => {
      const accountOwner1 = createAccountOwner()
      const factory = await new SimpleAccountFactory__factory(ethersSigner).deploy(entryPoint.address)
      const initCode = hexConcat([
        factory.address,
        factory.interface.encodeFunctionData('createAccount', [accountOwner1.address, 0])
      ])

      const sender = await factory.getAddress(accountOwner1.address, 0)

      const account = SimpleAccount__factory.connect(sender, ethersSigner)

      await fund(sender)
      const counter = await new TestCounter__factory(ethersSigner).deploy()

      const count = counter.interface.encodeFunctionData('count')
      const callData = account.interface.encodeFunctionData('execute', [counter.address, 0, count])
      // deliberately broken signature. simulate should work with it too.
      const userOp = await fillSignAndPack({
        sender,
        initCode,
        callData,
        callGasLimit: 1e5 // fillAndSign can't estimate calls during creation
      }, accountOwner1, entryPoint)
      const ret = await simulateHandleOp(userOp,
        counter.address,
        counter.interface.encodeFunctionData('counters', [account.address]),
        entryPoint.address)

      const [countResult] = counter.interface.decodeFunctionResult('counters', ret.targetResult)
      expect(countResult).to.equal(1)
      expect(ret.targetSuccess).to.be.true

      // actual counter is zero
      expect(await counter.counters(account.address)).to.equal(0)
    })

    it('should simulate execution', async () => {
      const accountOwner1 = createAccountOwner()
      const { proxy: account } = await createAccount(ethersSigner, await accountOwner.getAddress(), entryPoint.address)
      await fund(account)
      const counter = await new TestCounter__factory(ethersSigner).deploy()

      const count = counter.interface.encodeFunctionData('count')
      const callData = account.interface.encodeFunctionData('execute', [counter.address, 0, count])
      // deliberately broken signature. simulate should work with it too.
      const userOp = await fillSignAndPack({
        sender: account.address,
        callData
      }, accountOwner1, entryPoint)

      const ret = await simulateHandleOp(userOp,
        counter.address,
        counter.interface.encodeFunctionData('counters', [account.address]),
        entryPoint.address
      )

      const [countResult] = counter.interface.decodeFunctionResult('counters', ret.targetResult)
      expect(countResult).to.equal(1)
      expect(ret.targetSuccess).to.be.true

      // actual counter is zero
      expect(await counter.counters(account.address)).to.equal(0)
    })

    it('should simulate execution with verifyingpaymaster', async () => {
      const accountOwner1 = createAccountOwner()
      const { verifyingPaymaster } = await loadFixture(deployVerifyingPaymasterFixture(entryPoint.address));
      const { proxy: account } = await createAccount(ethersSigner, await accountOwner.getAddress(), entryPoint.address)
      await fund(account)
      const counter = await new TestCounter__factory(ethersSigner).deploy()

      const count = counter.interface.encodeFunctionData('count')
      const callData = account.interface.encodeFunctionData('execute', [counter.address, 0, count])
      // deliberately broken signature. simulate should work with it too.
      const partialUserOp = await fillAndSign(
        {
          sender: account.address,
          paymaster: verifyingPaymaster.address,
          paymasterData: ethers.utils.hexConcat([
            encodePaymasterData(),
            "0x" + "00".repeat(65),
          ]),
          callData
        },
        accountOwner1, entryPoint
      );
      const hash = await verifyingPaymaster.getHash(
        packUserOp(partialUserOp),
        MOCK_VALID_UNTIL,
        MOCK_VALID_AFTER,
        ethers.constants.AddressZero,
        ethers.constants.Zero,
      );
  
      const sig = await accountOwner1.signMessage(ethers.utils.arrayify(hash));
      const userOp = await fillSignAndPack(
        {
          ...partialUserOp,
          paymasterData: ethers.utils.hexConcat([
            encodePaymasterData(),
            sig,
          ]),
        },
        accountOwner1,
        entryPoint,
      );

      const ret = await simulateHandleOp(userOp,
        counter.address,
        counter.interface.encodeFunctionData('counters', [account.address]),
        entryPoint.address
      )

      const [countResult] = counter.interface.decodeFunctionResult('counters', ret.targetResult)
      expect(countResult).to.equal(1)
      expect(ret.targetSuccess).to.be.true

      // actual counter is zero
      expect(await counter.counters(account.address)).to.equal(0)
    })

    it('should simulate execution with verifyingpaymaster without calldata', async () => {
      const accountOwner1 = createAccountOwner()
      const { verifyingPaymaster } = await loadFixture(deployVerifyingPaymasterFixture(entryPoint.address));
      const { proxy: account } = await createAccount(ethersSigner, await accountOwner.getAddress(), entryPoint.address)
      await fund(account)

      const counter = await new TestCounter__factory(ethersSigner).deploy()
      const count = counter.interface.encodeFunctionData('count')
      const callData = account.interface.encodeFunctionData('execute', [counter.address, 0, count])

      
      const paymasterAndDataRaw = "0x3da96267b98a33267249734fd8ffec75093d3085000000000000000000000000004c4b40000000000000000000000000001e8480000000000000000000000000000000000000000000000000000000006c7bacd00000000000000000000000000000000000000000000000000000000065ed355000000000000000000000000086af7fa0d8b0b7f757ed6cdd0e2aadb33b03be580000000000000000000000000000000000000000000000000000000000000000a3ed5aac9cc9618d79df3d52e0de49122fad73bbe37774b972874e3a7d4735f37c31e43eae8a6054be887670c2a14b2b374055a924c00b6e8f8993e7b9d12e111c"
      const paymasterVerificationGasLimit = "0x"+paymasterAndDataRaw.slice(42, 74)
      const paymasterPostOpGasLimit = "0x"+paymasterAndDataRaw.slice(74, 106)
      const paymasterAndDataInfo = "0x"+paymasterAndDataRaw.slice(106, 362)
      const [validUntil, validAfter, token, rate, _] = await verifyingPaymaster.parsePaymasterAndData(paymasterAndDataRaw)
      const partialUserOp:PackedUserOperation = { 
        sender: account.address,
        nonce: "0",
        callData,
        accountGasLimits: "0x0000000000000000000000000005fa35000000000000000000000000000054fa",
        initCode: "0x",// "0x9406cc6185a346906296840746125a0e449764545fbfb9cf000000000000000000000000b6bcf9517d193f551d0e3d6860103972dd13de7b0000000000000000000000000000000000000000000000000000000000000000",
        preVerificationGas: "44644",
        gasFees: "0x00000000000000000000000059682f000000000000000000000000005968606e",
        paymasterAndData: "0x",
        signature: "0x"
      }
      const hash = await verifyingPaymaster.getHash(
        partialUserOp,
        validUntil,
        validAfter,
        token,
        rate,
      );
      const sig = await accountOwner1.signMessage(ethers.utils.arrayify(hash));
      const paymasterAndData = ethers.utils.hexConcat([
        verifyingPaymaster.address,
        paymasterVerificationGasLimit,
        paymasterPostOpGasLimit,
        paymasterAndDataInfo,
        sig])
      const userOp: PackedUserOperation = {
        sender: account.address,
        nonce: "0",
        callData,
        accountGasLimits: "0x0000000000000000000000000005fa35000000000000000000000000000054fa",
        initCode: "0x",//"0x9406cc6185a346906296840746125a0e449764545fbfb9cf000000000000000000000000b6bcf9517d193f551d0e3d6860103972dd13de7b0000000000000000000000000000000000000000000000000000000000000000",
        preVerificationGas: "44644",
        gasFees: "0x00000000000000000000000059682f000000000000000000000000005968606e",
        paymasterAndData,
        signature: "0x"
      }
      //sign packedUserOp
      const userOpSigned = await signPackedUserOp(userOp, accountOwner1, entryPoint)
      console.log("daniel log:userOpsigned:", userOpSigned)
      
      //const address_0 = "0x" + "00".repeat(20)
      const ret = await simulateHandleOp(userOpSigned,
        counter.address,
        counter.interface.encodeFunctionData('counters', [account.address]),
        entryPoint.address
      )
      console.log("daniel log:ret:", ret)

      const [countResult] = counter.interface.decodeFunctionResult('counters', ret.targetResult)
      //expect(countResult).to.equal(1)
      expect(ret.targetSuccess).to.be.true

      // actual counter is zero
      expect(await counter.counters(account.address)).to.equal(0)
    })
  })
})
