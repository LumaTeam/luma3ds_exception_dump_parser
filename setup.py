from setuptools import setup, find_packages

setup(
    name='luma3ds_exception_dump_parser',
    version='1.3.1',
    url='https://github.com/LumaTeam/luma3ds_exception_dump_parser',
    author='TuxSH',
    license='GPLv3',
    description='Parses Luma3DS exception dumps',
    install_requires=[''],
    packages=find_packages(),
    entry_points={'console_scripts': ['luma3ds_exception_dump_parser=luma3ds_exception_dump_parser.__main__:main']},
)
