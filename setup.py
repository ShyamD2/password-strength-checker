from setuptools import setup, find_packages

setup(
    name="advanced-password-strength-checker",
    version="1.0.0",
    description="Advanced CLI password strength checker with entropy analysis, "
                 "pattern detection, crack-time estimation, breach checking, "
                 "and policy compliance.",
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    install_requires=["rich>=13.7.0"],
    entry_points={
        "console_scripts": [
            "pwcheck=password_checker.cli:main",
        ],
    },
    python_requires=">=3.8",
)
