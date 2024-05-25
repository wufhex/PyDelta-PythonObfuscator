from setuptools import setup, find_packages

with open("README.md", "r") as f:
    desc = f.read()

setup(
    name='pydeltaobfuscator',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'cryptography',
        'argparse'
    ],
    entry_points={
        "console_scripts": [
            'pydelta-obfuscate = pydelta:obfuscate_cli',
        ],
    },
    long_description=desc,
    long_description_content_type="text/markdown"
)