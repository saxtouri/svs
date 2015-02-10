from setuptools import setup

setup(name='svs',
      version='0.0.1',
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
              'data/i18n/locales/*/LC_MESSAGES/*.mo',
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
      tests_require=["pytest", "mock"],
)
