from setuptools import setup, find_packages

setup(
    name='ogunscan',
    version='0.1.0',
    description='MCP server security scanner. Find vulnerabilities before attackers do.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Ten30 Studios',
    author_email='admin@ten30studio.com',
    url='https://ogunscan.dev',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    py_modules=['scanner'],
    entry_points={
        'console_scripts': [
            'ogunscan=scanner:cli',
        ],
    },
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='mcp security scanner ai agents claude cursor prompt-injection',
)
