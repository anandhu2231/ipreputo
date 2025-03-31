from setuptools import setup, find_packages

setup(
    name="ipreputo",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "pandas",
        "openpyxl",
    ],
    entry_points={
        "console_scripts": [
            "ipreputo=ipreputo.cli:main",
        ],
    },
)
