from setuptools import setup, find_packages

setup(
    name='prexl',
    version='0.1.0',
    description='Local, open-source 2FA CLI tool for TOTP code generation',
    author='Oyefeso Afolabi',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'pyotp',
        'cryptography',
        'click',
    ],
    entry_points={
        'console_scripts': [
            'prexl=prexl.__main__:cli',
        ],
    },
    python_requires='>=3.7',
    include_package_data=True,
) 