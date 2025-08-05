from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="netsec-scan",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Network Scanner & Vulnerability Detector",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/netsec-scan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "python-nmap>=0.7.1",
        "colorama>=0.4.4",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "netsec-scan=main:main",
        ],
    },
)
