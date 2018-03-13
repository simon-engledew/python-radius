from setuptools import setup

setup(
    name='python-radius',
    version='2.0',

    description='Pure python radius implementation which supports Message-Authenticator and Status-Server.',
    author="Simon Engledew",
    author_email="simon@engledew.com",
    url="http://www.engledew.com",
    py_modules=['radius'],
    extras_require = {
      'tests': [
        'pytest'
      ]
    },
    zip_safe=True,
    include_package_data=False,
    license='MIT',
    keywords = [
        'radius',
        'Message-Authenticator',
        'Status-Server'
    ],
    classifiers = [
        'Development Status :: 1 - Planning',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
)
