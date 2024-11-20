from setuptools import setup, find_packages

setup(
    name="threat_intel_framework",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        line.strip()
        for line in open("requirements.txt").readlines()
        if not line.startswith("#")
    ],
    entry_points={
        'console_scripts': [
            'threat-intel=src.cli.cli:cli',
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="A framework for threat intelligence data integration and analysis",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/threat_intel_framework",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
