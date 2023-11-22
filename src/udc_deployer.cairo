%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import deploy

@external
func __validate__{}(class_hash: felt) {
    return ();
}

@external
func __validate_deploy__{}(class_hash: felt, contract_address_salt: felt) {
    return ();
}

@external
func __validate_declare__{}(class_hash: felt) {
    return ();
}

@external
func __execute__{syscall_ptr: felt*}(class_hash: felt) -> (response_len: felt, response: felt*) {
    let (calldata: felt*) = alloc();

    deploy(
        class_hash=class_hash,
        contract_address_salt=0,
        constructor_calldata_size=0,
        constructor_calldata=calldata,
        deploy_from_zero=1,
    );

    let (response: felt*) = alloc();
    return (response_len=0, response=response);
}
