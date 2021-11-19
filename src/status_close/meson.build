status_close_sources = run_command(
    'find', '.', '(', '-name', '*.c', '-or', '-name', '*.h' , ')', 
    check : true
).stdout().strip().split('\n')

status_close_exe = executable(
    'status_close',
    status_close_sources,
    include_directories : it_include,
    dependencies : [threads, vcblockchain, vctool],
    link_with : it_helper_lib
)
