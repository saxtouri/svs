from setuptools.command.install import install as install_

from babel.messages.frontend import compile_catalog
import pkg_resources

from setuptools import setup


class compile_all_catalogs(compile_catalog):
    """Inspired by http://pfacka.binaryparadise.com/articles/localization-of-webapplications-with-babel.html
    """

    def initialize_options(self):
        compile_catalog.initialize_options(self)
        self.directory = pkg_resources.resource_filename('svs', 'data/i18n/locales')

    def finalize_options(self):
        compile_catalog.finalize_options(self)
        self.ensure_dirname('directory')

    def get_outputs(self):
        # necessary to be able to use 'pip install'
        return []


class install(install_):
    sub_commands = install_.sub_commands + [('compile_all_catalogs', None)]


setup(name='svs',
      version='0.1.0',
      description='The InAcademia Simple validation Service allows for the easy validation of affiliation (Student,'
                  'Faculty, Staff) of a user in Academia',
      license='Apache 2.0',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 2.7',
      ],
      author='DIRG',
      author_email='tech@inacademia.org',
      zip_safe=False,
      url='http://www.inacademia.org',
      packages=['svs'],
      package_data={
          'svs': [
              'data/i18n/locales/*/LC_MESSAGES/*.po',
              'templates/*.mako',
              'site/static/*',
          ],
      },
      package_dir={'': 'src'},
      entry_points={
          'console_scripts': ['inacademia=svs.inacademia_server:main'],
      },
      message_extractors={
          'src': [
              ('**.py', 'python', None),
              ('**/templates/**.mako', 'mako', None)
          ]
      },
      cmdclass={
          'install': install,
          'compile_all_catalogs': compile_all_catalogs
      },
      setup_requires=['Babel'],
      install_requires=['Babel', 'oic>=0.7.8'],
      tests_require=['pytest', 'mock'],
)
