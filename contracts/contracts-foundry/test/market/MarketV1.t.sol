// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MarketV1} from "../../src/market/MarketV1.sol";
import {ICredit} from "../../src/token/ICredit.sol";

contract ERC20Mock is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
    function mint(address account, uint256 amount) public {
        _mint(account, amount);
    }
}

contract CreditMock is ERC20Mock, ICredit {
    ERC20Mock public usdc;
    constructor(ERC20Mock _usdc) ERC20Mock("Credit", "CREDIT") {
        usdc = _usdc;
    }
    function redeemAndBurn(address to, uint256 amount) external {
        _burn(msg.sender, amount);
        usdc.transfer(to, amount);
    }
}

contract MarketV1Test is Test {
    MarketV1 marketv1;
    ERC20Mock token;
    CreditMock creditToken;

    address admin = address(1);
    address user = address(2);
    address provider = address(3);
    address user2 = address(4);
    address admin2 = address(5);

    uint256 constant ONE_MINUTE = 60;
    uint256 constant TWO_MINUTES = 60 * 2;
    uint256 constant FIVE_MINUTES = 60 * 5;
    uint256 constant NOTICE_PERIOD = FIVE_MINUTES;

    uint256 constant SIGNER1_INITIAL_FUND = 1000 * 10**6;
    uint256 constant SIGNER2_INITIAL_FUND = 1000 * 10**6;
    uint256 constant JOB_RATE_1 = 1 * 10**16; // 0.01 USDC/s

    bytes32 INITIAL_JOB_INDEX;
    uint256 JOB_OPENED_TIMESTAMP;
    uint256 INITIAL_TIMESTAMP;

    function setUp() public {
        token = new ERC20Mock("Pond", "POND");
        token.mint(user, SIGNER1_INITIAL_FUND);
        token.mint(user2, SIGNER2_INITIAL_FUND);

        creditToken = new CreditMock(token);
        token.mint(address(creditToken), 1000000 * 10**6);

        address proxy = Upgrades.deployUUPSProxy(
            "MarketV1.sol",
            abi.encodeCall(MarketV1.initialize, (admin, address(token)))
        );
        marketv1 = MarketV1(proxy);

        vm.startPrank(admin);
        marketv1.reinitialize(FIVE_MINUTES, address(creditToken));
        marketv1.updateNoticePeriod(FIVE_MINUTES);
        vm.stopPrank();

        vm.warp(1000000);
        INITIAL_TIMESTAMP = block.timestamp;

        creditToken.mint(admin, 1000 * 10**6);
        vm.prank(admin);
        creditToken.transfer(user, 1000 * 10**6);

        INITIAL_JOB_INDEX = marketv1.jobIndex();
    }

    function calcNoticePeriodCost(uint256 rate) internal pure returns (uint256) {
        return calcAmountToPay(rate, NOTICE_PERIOD);
    }
    
    function calcAmountToPay(uint256 rate, uint256 duration) internal pure returns (uint256) {
        uint256 decimals = 10**12;
        return (rate * duration + decimals - 1) / decimals;
    }

    function usdc(uint256 amount) internal pure returns (uint256) {
        return amount * 10**6;
    }

    function test_ProviderRegisters() public {
        vm.prank(user);
        marketv1.providerAdd("https://example.com/");
        (string memory cp) = marketv1.providers(user);
        assertEq(cp, "https://example.com/");
    }

    function test_ProviderRegistersRevertsEmptyCp() public {
        vm.prank(user);
        vm.expectRevert("invalid");
        marketv1.providerAdd("");
    }

    function test_ProviderRegistersRevertsAlreadyRegistered() public {
        vm.prank(user);
        marketv1.providerAdd("https://example.com/");

        vm.prank(user);
        vm.expectRevert("already exists");
        marketv1.providerAdd("https://example.com/");
    }

    function test_ProviderUnregisters() public {
        vm.prank(user);
        marketv1.providerAdd("https://example.com/");
        vm.prank(user);
        marketv1.providerRemove();

        (string memory cp) = marketv1.providers(user);
        assertEq(cp, "");
    }

    function test_ProviderUnregistersRevertsNeverRegistered() public {
        vm.prank(user);
        vm.expectRevert("not found");
        marketv1.providerRemove();
    }

    function test_ProviderUnregistersRevertsAlreadyUnregistered() public {
        vm.prank(user);
        marketv1.providerAdd("https://example.com/");
        vm.prank(user);
        marketv1.providerRemove();

        vm.prank(user);
        vm.expectRevert("not found");
        marketv1.providerRemove();
    }

    function test_ProviderUpdateWithCp() public {
        vm.prank(user);
        marketv1.providerAdd("https://example.com/");
        vm.prank(user);
        marketv1.providerUpdateWithCp("https://example.com/new");

        (string memory cp) = marketv1.providers(user);
        assertEq(cp, "https://example.com/new");
    }

    function test_ProviderUpdateWithCpRevertsEmptyCp() public {
        vm.prank(user);
        marketv1.providerAdd("https://example.com/");
        vm.prank(user);
        vm.expectRevert("invalid");
        marketv1.providerUpdateWithCp("");
    }

    function test_ProviderUpdateWithCpRevertsNeverRegistered() public {
        vm.prank(user);
        vm.expectRevert("not found");
        marketv1.providerUpdateWithCp("https://example.com/new");
    }

    function test_JobOpen_with_USDC_only() public {
        uint256 initialBalance = usdc(50);
        uint256 noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        token.approve(address(marketv1), initialBalance);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialBalance);
        vm.stopPrank();

        (string memory metadata, address owner_, address provider_, uint256 rate, uint256 balance, uint256 lastSettled, uint256 maxRate) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(metadata, "some metadata");
        assertEq(owner_, user);
        assertEq(provider_, provider);
        assertEq(rate, JOB_RATE_1);
        assertEq(balance, initialBalance - noticePeriodCost);
        assertEq(lastSettled, block.timestamp);
        assertEq(maxRate, JOB_RATE_1);

        assertEq(token.balanceOf(user), SIGNER1_INITIAL_FUND - initialBalance);
        assertEq(token.balanceOf(address(marketv1)), initialBalance - noticePeriodCost);
    }

    function test_JobOpen_increments_job_index_correctly() public {
        uint256 initialBalance = usdc(10);
        bytes32 initialJobIndex = marketv1.jobIndex();

        vm.startPrank(user);
        token.approve(address(marketv1), initialBalance * 3);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialBalance);
        
        (string memory metadata, , , , , , ) = marketv1.jobs(initialJobIndex);
        assertEq(metadata, "some metadata");

        marketv1.jobOpen("some metadata2", provider, JOB_RATE_1, initialBalance);
        bytes32 secondJobId = bytes32(uint256(initialJobIndex) + 1);
        (metadata, , , , , , ) = marketv1.jobs(secondJobId);
        assertEq(metadata, "some metadata2");

        marketv1.jobOpen("some metadata3", provider, JOB_RATE_1, initialBalance);
        bytes32 thirdJobId = bytes32(uint256(initialJobIndex) + 2);
        (metadata, , , , , , ) = marketv1.jobs(thirdJobId);
        assertEq(metadata, "some metadata3");
        vm.stopPrank();
    }

    function test_JobOpen_with_Credit_only() public {
        uint256 initialBalance = usdc(50);
        uint256 noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        creditToken.approve(address(marketv1), initialBalance);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialBalance);
        vm.stopPrank();

        (string memory metadata, address owner_, address provider_, uint256 rate, uint256 balance, uint256 lastSettled, ) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(metadata, "some metadata");
        assertEq(owner_, user);
        assertEq(provider_, provider);
        assertEq(rate, JOB_RATE_1);
        assertEq(balance, initialBalance - noticePeriodCost);
        assertEq(lastSettled, block.timestamp);

        assertEq(marketv1.jobCreditBalance(INITIAL_JOB_INDEX), initialBalance - noticePeriodCost);
    }

    function test_JobOpen_with_USDC_and_Credit() public {
        uint256 totalBalance = usdc(50);
        uint256 creditBalance = usdc(10);
        uint256 noticePeriodCost = calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        token.approve(address(marketv1), totalBalance);
        creditToken.approve(address(marketv1), creditBalance);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, totalBalance);
        vm.stopPrank();

        (string memory metadata, address owner_, address provider_, uint256 rate, uint256 balance, , ) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(metadata, "some metadata");
        assertEq(owner_, user);
        assertEq(provider_, provider);
        assertEq(rate, JOB_RATE_1);
        assertEq(balance, totalBalance - noticePeriodCost);
        assertEq(marketv1.jobCreditBalance(INITIAL_JOB_INDEX), creditBalance - noticePeriodCost);
    }

    function test_JobOpen_reverts_without_enough_approved() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("ERC20InsufficientAllowance(address,uint256,uint256)", address(marketv1), 0, usdc(150)));
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, usdc(150));
    }

    function test_JobOpen_reverts_without_enough_balance() public {
        vm.startPrank(user);
        token.approve(address(marketv1), usdc(5000));
        vm.expectRevert(abi.encodeWithSignature("ERC20InsufficientBalance(address,uint256,uint256)", user, token.balanceOf(user), usdc(5000)));
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, usdc(5000));
        vm.stopPrank();
    }

    function test_JobSettle_immediately() public {
        uint256 initialDeposit = usdc(50);
        uint256 initialBalance = initialDeposit - calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        token.approve(address(marketv1), initialDeposit);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);
        
        marketv1.jobSettle(INITIAL_JOB_INDEX);
        vm.stopPrank();

        ( , , , , uint256 balance, uint256 lastSettled, ) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(balance, initialBalance);
        assertEq(lastSettled, block.timestamp);
    }

    function test_JobSettle_after_2_minutes() public {
        uint256 initialDeposit = usdc(50);
        uint256 initialBalance = initialDeposit - calcNoticePeriodCost(JOB_RATE_1);

        vm.startPrank(user);
        token.approve(address(marketv1), initialDeposit);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);
        uint256 openTimestamp = block.timestamp;
        vm.stopPrank();

        vm.warp(block.timestamp + TWO_MINUTES);

        vm.prank(user);
        marketv1.jobSettle(INITIAL_JOB_INDEX);

        ( , , , , uint256 balance, uint256 lastSettled, ) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(lastSettled, openTimestamp + TWO_MINUTES);
        assertEq(balance, initialBalance - calcAmountToPay(JOB_RATE_1, TWO_MINUTES));
    }

    function test_JobDeposit_USDC() public {
        uint256 initialDeposit = usdc(50);
        uint256 additionalDeposit = usdc(25);

        vm.startPrank(user);
        token.approve(address(marketv1), initialDeposit + additionalDeposit);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);
        
        uint256 balanceBefore = token.balanceOf(address(marketv1));
        marketv1.jobDeposit(INITIAL_JOB_INDEX, additionalDeposit);
        vm.stopPrank();

        ( , , , , uint256 balance, , ) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(balance, initialDeposit - calcNoticePeriodCost(JOB_RATE_1) + additionalDeposit);
        assertEq(token.balanceOf(address(marketv1)), balanceBefore + additionalDeposit);
    }

    function test_JobWithdraw_USDC() public {
        uint256 initialDeposit = usdc(50);
        uint256 withdrawAmount = usdc(10);

        vm.startPrank(user);
        token.approve(address(marketv1), initialDeposit);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);
        
        marketv1.jobWithdraw(INITIAL_JOB_INDEX, withdrawAmount);
        vm.stopPrank();

        ( , , , , uint256 balance, , ) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(balance, initialDeposit - calcNoticePeriodCost(JOB_RATE_1) - withdrawAmount);
    }

    function test_JobReviseRate_higher() public {
        uint256 initialDeposit = usdc(50);
        uint256 initialBalance = initialDeposit - calcNoticePeriodCost(JOB_RATE_1);
        uint256 higherRate = 2 * 10**16;

        vm.startPrank(user);
        token.approve(address(marketv1), initialDeposit);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        marketv1.jobReviseRate(INITIAL_JOB_INDEX, higherRate);
        vm.stopPrank();

        ( , , , uint256 rate, uint256 balance, , uint256 maxRate) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(rate, higherRate);
        assertEq(maxRate, higherRate);
        assertEq(balance, initialBalance - calcNoticePeriodCost(higherRate - JOB_RATE_1));
    }

    function test_JobClose() public {
        uint256 initialDeposit = usdc(50);

        vm.startPrank(user);
        token.approve(address(marketv1), initialDeposit);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        marketv1.jobClose(INITIAL_JOB_INDEX);
        vm.stopPrank();

        (string memory metadata, address owner_, , uint256 rate, uint256 balance, , ) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(metadata, "");
        assertEq(owner_, address(0));
        assertEq(rate, 0);
        assertEq(balance, 0);

        assertEq(token.balanceOf(user), SIGNER1_INITIAL_FUND - calcNoticePeriodCost(JOB_RATE_1));
    }

    function test_JobMetadataUpdate() public {
        uint256 initialDeposit = usdc(50);

        vm.startPrank(user);
        token.approve(address(marketv1), initialDeposit);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, initialDeposit);

        marketv1.jobMetadataUpdate(INITIAL_JOB_INDEX, "new metadata");
        vm.stopPrank();

        (string memory metadata, , , , , , ) = marketv1.jobs(INITIAL_JOB_INDEX);
        assertEq(metadata, "new metadata");
    }

    function test_EmergencyWithdraw() public {
        bytes32 role = marketv1.EMERGENCY_WITHDRAW_ROLE();
        vm.prank(admin);
        marketv1.grantRole(role, admin2);

        uint256 deposit = usdc(50);
        vm.startPrank(user);
        creditToken.approve(address(marketv1), deposit);
        marketv1.jobOpen("some metadata", provider, JOB_RATE_1, deposit);
        vm.stopPrank();

        bytes32[] memory jobs = new bytes32[](1);
        jobs[0] = INITIAL_JOB_INDEX;

        vm.prank(admin);
        marketv1.emergencyWithdrawCredit(admin2, jobs);

        assertEq(marketv1.jobCreditBalance(INITIAL_JOB_INDEX), 0);
        assertGt(creditToken.balanceOf(admin2), 0);
    }
}
