project('pycrypto_rsa_legacy', 'c')

py = import('python').find_installation(pure: false)

gmp = dependency('gmp', required : false)

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

if gmp.found()
    py.extension_module(
        '_plain_rsa_key',
        extension_sources,
        install: true,
        subdir: 'pycrypto_rsa_legacy',
        dependencies: [gmp]
    )
endif