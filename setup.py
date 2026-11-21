from setuptools import setup, find_packages

setup(
    name="log-detective",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.0.0",
        "orjson>=3.9.0",
        "pydantic>=2.0.0"
    ],
    entry_points={
        "console_scripts": [
            "log-detective=log_detective.cli:main",
            "logdet=log_detective.cli:main",
        ]
    },
)
