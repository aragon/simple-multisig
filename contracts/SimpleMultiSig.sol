pragma solidity 0.4.15;
contract SimpleMultiSig {

  uint public nonce;
  uint public threshold;
  mapping (address => bool) isOwner;
  address[] public ownersArr;

  function SimpleMultiSig(uint threshold_, address[] owners_) {
    setupWallet(threshold_, owners_);
  }

  function setupWallet(uint threshold_, address[] owners_) {
    // either wallet performs action to itself or it is first setup
    require(msg.sender == address(this) || threshold == 0);
    require(owners_.length <= 10 && threshold_ <= owners_.length && threshold_ != 0);

    for (uint j=0; j<ownersArr.length; j++) {
        isOwner[ownersArr[j]] = false;  // clean up old owners if any
    }

    address lastAdd = address(0);
    for (uint i=0; i<owners_.length; i++) {
      require(owners_[i] > lastAdd);
      isOwner[owners_[i]] = true;
      lastAdd = owners_[i];
    }
    ownersArr = owners_;
    threshold = threshold_;
  }

  // Note that address recovered from signatures must be strictly increasing
  function execute(uint8[] sigV, bytes32[] sigR, bytes32[] sigS, address destination, uint value, bytes data) {
    require(sigR.length == threshold);
    require(sigR.length == sigS.length && sigR.length == sigV.length);

    // Follows ERC191 signature scheme: https://github.com/ethereum/EIPs/issues/191
    bytes32 txHash = keccak256(byte(0x19), byte(0), this, destination, value, data, nonce);

    address lastAdd = address(0); // cannot have address(0) as an owner
    for (uint i = 0; i < threshold; i++) {
        address recovered = ecrecover(txHash, sigV[i], sigR[i], sigS[i]);
        require(recovered > lastAdd && isOwner[recovered]);
        lastAdd = recovered;
    }

    // If we make it here all signatures are accounted for
    nonce = nonce + 1;
    require(destination.call.value(value)(data));
  }

  function () payable {}
}
