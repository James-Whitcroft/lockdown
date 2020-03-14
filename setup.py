import os

try:
  from setuptools import setup
  from setuptools import find_packages
  packages = find_packages()
except ImportError:
  from distutils.core import setup
  packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

install_requires = [
  'psutil>=5.6.6'
]

setup(
    name='lockdown',
    version='0.0.1',
    packages=packages,
    include_package_data=True,
    zip_safe=False,
    install_requires = install_requires,
    entry_points ={
    'console_scripts': ['lockdown = lockdown.exec:main_func'],
    }
)

