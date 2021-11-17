submit_multiple_txns_sources = run_command(
    'find', '.', '(', '-name', '*.c', '-or', '-name', '*.h' , ')', 
    check : true
).stdout().strip().split('\n')

submit_multiple_txns_exe = executable(
    'submit_multiple_txns',
    submit_multiple_txns_sources,
    include_directories : it_include,
    dependencies : [threads, vcblockchain, vctool],
    link_with : it_helper_lib
)
