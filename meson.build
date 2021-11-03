project('v-c-it', 'c', 'cpp',
    version : '0.4.3-snapshot',
    default_options : ['c_std=gnu11', 'cpp_std=c++14', 'buildtype=release'],
    meson_version : '>=0.53.0'
)

message('Using build type: ' + get_option('buildtype'))

force_velo_toolchain = get_option('force_velo_toolchain')

# TODO: Move this into meson's built in warning level.
add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'c')
add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'cpp')

it_helper_lib_src = run_command(
    'find', './src/helpers', '(', '-name', '*.c', '-or', '-name', '*.h' , ')', 
    check : true
).stdout().strip().split('\n')

it_include = include_directories('include')

vcblockchain = dependency(
    'vcblockchain',
    required : true,
    fallback : ['vcblockchain', 'vcblockchain_dep']
)

agentd = dependency(
    'agentd',
    required : true,
    fallback : ['agentd', 'agentd_dep']
)

vctool = dependency(
    'vctool',
    required : true,
    fallback : ['vctool', 'vctool_dep']
)

threads = dependency('threads')

it_helper_lib = static_library('it-helper', it_helper_lib_src,
    include_directories: it_include,
    dependencies : [vcblockchain, vctool]
)

subdir('src')
