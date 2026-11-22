from setuptools import setup, find_packages

setup(
    name="log-detective",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[],
    entry_points={"console_scripts": [
        "log-detective=log_detective.cli:main",
        "logdet=log_detective.cli:main",
    ]},
)
