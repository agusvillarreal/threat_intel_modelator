from setuptools import setup, find_packages
import os

def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname), 'r', encoding='utf-8') as f:
        return f.read()

def read_requirements(fname):
    with open(fname, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="threat_intel_framework",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A framework for threat intelligence data integration and analysis",
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/threat_intel_framework",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    python_requires=">=3.12",
    install_requires=read_requirements('requirements.txt'),
    entry_points={
        'console_scripts': [
            'threat-intel=src.cli.cli:cli',
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.12",
    ],
)