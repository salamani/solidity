contract C {
	uint[] storageArray;
	function test_indicies(uint256 len) public
	{
		storageArray.length = len;

		for (uint i = 0; i < len; i++)
			storageArray[i] = i + 1;

		for (uint i = 0; i < len; i++)
			require(storageArray[i] == i + 1);
	}

	function test_zeroed_indicies(uint256 len) public
	{
		storageArray.length = len;

		for (uint i = 0; i < len; i++)
			storageArray[i] = i + 1;

		storageArray.length = 0;
		storageArray.length = len;

		for (uint i = 0; i < len; i++)
		{
			require(storageArray[i] == 0);

			uint256 val = storageArray[i];
			uint256 check;

			assembly { check := iszero(val) }

			require(check == 1);
		}
	}
}
// ====
// compileViaYul: true
// ----
// test_indicies(uint256): 1 ->
// test_indicies(uint256): 129 ->
// test_indicies(uint256): 5 ->
// test_indicies(uint256): 10 ->
// test_indicies(uint256): 15 ->
// test_indicies(uint256): 0xFF ->
// test_indicies(uint256): 1000 ->
// test_indicies(uint256): 129 ->
// test_indicies(uint256): 128 ->
// test_indicies(uint256): 1 ->
// test_zeroed_indicies(uint256): 1 ->
// test_zeroed_indicies(uint256): 5 ->
// test_zeroed_indicies(uint256): 10 ->
// test_zeroed_indicies(uint256): 15 ->
// test_zeroed_indicies(uint256): 0xFF ->
