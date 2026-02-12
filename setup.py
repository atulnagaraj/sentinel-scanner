from setuptools import setup, find_packages

setup(
    name="sentinel-scanner",
    version="1.0.0",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "sentinel=sentinel.cli:main",
        ],
    },
    python_requires=">=3.9",
    author="Security Research Team",
    description="Production-grade Smart Contract Security Framework",
)
