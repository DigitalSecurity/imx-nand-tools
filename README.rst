i.MX NAND Tools for Freescale i.MX NAND Dumps
=============================================

Provides dedicated tools for IMX NAND dumps reverse-engineering:

* **imx-nand-info**: parse the FCB and display useful information about the Flash structure
* **imx-nand-convert**: parse the FCB and convert the actual dump into a memory-based image that can be processed with binwalk

How to install
==============

You can choose to either install *imx-nand-tools* from PyPi or from the source.

PyPi install
------------

That's the most easiest way to install *imx-nand-tools*:

::

        $ sudo pip3 install imx-nand-tools


It will install *imx-nand-tools* and all its dependencies. 


Install from source
-------------------

The following commands will install *imx-nand-tools* from source.

::

        $ git clone https://github.com/DigitalSecurity/imx-nand-tools.git
        $ sudo pip install setuptools
        $ cd imx-nand-tools
        $ python setup.py build
        $ sudo python setup.py install 

And that's it


How to use it
=============

imx-nand-info
-------------

This tool loooks for the first *Firmware Control Block* (FCB) contained in a dump and parse it and then
displays its contents.

::

        $ imx-nand-info fresh-dump.bin


imx-nand-convert
----------------

This tool converts a fresh i.MX NAND dump into a useable memory image:

::
  
        $ imx-nand-convert fresh-dump.bin converted-dump.bin


The *-c* option enables error correction thanks to embedded ECC information, thus *imx-nand-convert* will be able to fix potential errors in the original NAND dump.


