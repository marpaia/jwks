import pathlib
from setuptools import setup

DIR = pathlib.Path(__file__).parent
README = (DIR / "README.md").read_text()

setup(
    name="jwks",
    version="1.0.0",
    description="A lightweight Python library for using JSON Web Key Sets",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/marpaia/jwks",
    author="Mike Arpaia",
    author_email="mike@arpaia.co",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
    ],
    packages=["jwks"],
    include_package_data=True,
    install_requires=["jose", "pydantic", "requests"],
)
