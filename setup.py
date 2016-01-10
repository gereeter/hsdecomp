from setuptools import setup

setup(
    name = 'hsdecomp',
    version = '0.1.0',
    description = 'A decompiler for GHC-compiled Haskell',
    url = 'https://github.com/gereeter/hsdecomp',
    author = 'Jonathan S',
    author_email = 'gereeter+code@gmail.com',
    license = 'MIT',
    packages = ['hsdecomp'],
    install_requires = [
        'pyelftools',
        'capstone'
    ],
    entry_points = {
        'console_scripts': [
            'hsdecomp = hsdecomp:main'
        ]
    }
)
