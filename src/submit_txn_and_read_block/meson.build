submit_txn_and_read_block_sources = run_command(
    'find', '.', '(', '-name', '*.c', '-or', '-name', '*.h' , ')', 
    check : true
).stdout().strip().split('\n')

submit_txn_and_read_block_exe = executable(
    'submit_txn_and_read_block',
    submit_txn_and_read_block_sources,
    include_directories : it_include,
    dependencies : [threads, vcblockchain, vctool],
    link_with : it_helper_lib
)
