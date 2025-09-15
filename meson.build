project('pycrypto_rsa_legacy', 'c')

py = import('python').find_installation(pure: false)

if meson.get_compiler('c').get_id() in ['msvc']
    link_args = ['gmp.lib']
else
    link_args = ['-lgmp']
endif

module_sources = [
    'src/pycrypto_rsa_legacy/__init__.py',
    'src/pycrypto_rsa_legacy/plain_rsa_key.py',
    'src/pycrypto_rsa_legacy/_plain_rsa_key.pyi',
]

py.install_sources(
    module_sources,
    subdir: 'pycrypto_rsa_legacy',
    pure: false
)

extension_sources = [
    'src/pycrypto_rsa_legacy/plain_rsa_key.c'
]

py.extension_module(
    '_plain_rsa_key',
    extension_sources,
    install: true,
    subdir: 'pycrypto_rsa_legacy',
    link_args: link_args
)