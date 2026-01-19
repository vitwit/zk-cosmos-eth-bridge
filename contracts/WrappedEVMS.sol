pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract WrappedEVMS is ERC20 {
    constructor() ERC20("Wrapped EVMS", "wEVMS") {}
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
