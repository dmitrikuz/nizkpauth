from setuptools import setup, find_packages
setup(
    name='nizkpauth',
    version='1.0',
    packages=find_packages(),
    install_requires=['pycryptodome==3.18.0', 'dataclasses-json==0.6.1'],
    entry_points={
        'console_scripts': ['nizkpauth=nizkpauth.main:main']
    },
)