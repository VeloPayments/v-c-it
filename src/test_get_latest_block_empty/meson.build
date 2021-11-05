test_get_latest_block_empty_sources = run_command(
    'find', '.', '(', '-name', '*.c', '-or', '-name', '*.h' , ')', 
    check : true
).stdout().strip().split('\n')

test_get_latest_block_empty_exe = executable(
    'test_get_latest_block_empty',
    test_get_latest_block_empty_sources,
    include_directories : it_include,
    dependencies : [threads, vcblockchain, vctool],
    link_with : it_helper_lib
)
