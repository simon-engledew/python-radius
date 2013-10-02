from setuptools import setup, find_packages

setup(
    name='python-radius',
    version='1.0',

    description='Pure python radius implementation which supports Message-Authenticator and Status-Server.',
    author="Simon Engledew",
    author_email="simon@engledew.com",
    url="http://www.engledew.com",

    install_requires = [
    ],
    zip_safe=True,
    include_package_data=False,
    packages=find_packages(),
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