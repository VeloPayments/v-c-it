ping_client_sources = run_command(
    'find', '.', '(', '-name', '*.c', '-or', '-name', '*.h' , ')', 
    check : true
).stdout().strip().split('\n')

ping_client_exe = executable(
    'ping_client',
    ping_client_sources,
    include_directories : it_include,
    dependencies : [threads, vcblockchain, vctool],
    link_with : it_helper_lib
)
