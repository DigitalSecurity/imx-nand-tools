import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "imx-nand-tools",
    version = "1.0.3",
    python_requires='>3.5.2',
    url='https://github.com/DigitalSecurity/imx-nand-tools',
    author = "Damien Cauquil",
    author_email = "damien.cauquil@digital.security",
    description = ("Freescale i.MX NAND reverse tools"),
    long_description=read("README.rst"),
    license = "MIT",
    keywords = "imx freescale tool",
    packages=['imxtools'],
    install_requires=[
            'progressbar2',
            'termcolor',
            'bchlib'
    ],
    entry_points= {
        'console_scripts': [
            'imx-nand-info=imxtools.imx_nand_info:main',
            'imx-nand-convert=imxtools.imx_nand_convert:main'
        ]
    },
)
