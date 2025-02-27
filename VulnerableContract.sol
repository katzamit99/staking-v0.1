pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    bool public isLocked;
    uint256 public totalFunds;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Vulnerability 1: Unprotected ether withdrawal (anyone can drain contract)
    function withdrawAll() public {
        uint256 amount = address(this).balance;
        payable(msg.sender).transfer(amount);
    }
    
    // Vulnerability 2: Reentrancy vulnerability
    function withdrawBalance() public {
        uint256 amount = balances[msg.sender];
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");
        balances[msg.sender] = 0;
    }
    
    // Vulnerability 3: Integer overflow/underflow + no input validation
    function deposit(uint256 amount) public payable {
        unchecked {
            balances[msg.sender] = balances[msg.sender] + amount;
            totalFunds = totalFunds + amount;
        }
    }
    
    // Vulnerability 4: Unrestricted owner change
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }
    
    // Vulnerability 5: Delegatecall to untrusted address
    function execute(address target, bytes memory data) public returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return returndata;
    }
    
    // Vulnerability 6: Hardcoded sensitive data + selfdestruct
    address public secretAddress = 0x1234567890123456789012345678901234567890;
    function destroyContract() public {
        selfdestruct(payable(secretAddress));
    }
    
    // Vulnerability 7: Unchecked external call
    function callExternal(address target) public {
        (bool success, ) = target.call(abi.encodeWithSignature("doSomething()"));
        // No check on success
    }
    
    // Vulnerability 8: Public state-changing function with no access control
    function updateTotalFunds(uint256 newTotal) public {
        totalFunds = newTotal;
    }
    
    // Vulnerability 9: Denial of Service via external dependency
    function batchTransfer(address[] memory recipients, uint256 amount) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(amount);
        }
    }
}