from distutils.core import setup, Extension
import os


PACKAGE = 'udns'
SOURCES = [
    'udns/mod_udns.c',
]

README = open('README.rst').read().strip() if os.path.isfile('README.rst') else ''

udns_module = Extension('udns._udns', SOURCES,
                        libraries=['udns'],
                        language='c')

setup(name='pyudns',
      version='0.1',
      author='Sergey Shepelev',
      author_email='temotor@gmail.com',
      url='http://github.com/temoto/pyudns',
      packages=[PACKAGE],
      description="pyudns is python binding to udns library by Michael Tokarev.",
      long_description=README,
      ext_modules=[udns_module],
      license='MIT License',
     )
