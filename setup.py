#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Setup script for JS Analyzer CLI
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="jsanalyzer",
    version="1.0.1",
    author="0std1",
    author_email="",
    description="JavaScript static analysis tool for extracting endpoints, URLs, secrets, and more",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/etyvrox/jsanalyzer",
    py_modules=["js_analyzer_engine"],
    scripts=["jsanalyzer"],
    install_requires=requirements,
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
