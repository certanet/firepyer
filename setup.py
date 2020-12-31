import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="firepyer",
    version="0.0.1",
    author="Marcus Cockerill",
    author_email="marcus@certa.network",
    description="Interacting with Cisco FTD devices via the FDM REST API in Python",
    keywords='cisco firepower fdm ftd rest api python',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/certanet/firepyer",
    packages=setuptools.find_packages(),
    install_requires=['requests'],
    classifiers=[
        'Development Status :: 1 - Planning',
        'Intended Audience :: Developers',
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    python_requires='>=3.6',
)