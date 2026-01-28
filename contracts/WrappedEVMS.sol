pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

contract WrappedEVMS is ERC20, ERC20Burnable {
    address public bridge;

    constructor() ERC20("Wrapped EVMS", "wEVMS") {
        bridge = msg.sender;
    }

    function setBridge(address _bridge) external {
        require(msg.sender == bridge, "only bridge"); // simplistic owner check for PoC
        bridge = _bridge;
    }

    function mint(address to, uint256 amount) external {
        // ideally restrict to bridge
        _mint(to, amount);
    }
}
