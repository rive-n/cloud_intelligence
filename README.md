# cloud_intelligence - K8S OSINT tool.
![logo](https://github.com/rive-n/cloud_intelligence/blob/master/cloud_intelligence.png)

# Why is it profitable to use this tool?
1. Speed.
    * The asynchronous programming paradigm was taken as the basis. Therefore, almost all methods use asynchronous handlers
2. Coverage.
    * This tool covers virtually all known k8s instances. For example - checks all API of RHOCP
3. Effectiveness.
    * Except for all of the above, there is support for beautiful tabular output, which allows you to get a complete understanding of the infrastructure under study 

# Installation & Usage
## Installation

This point can also be referred to benefits. Installation is very simple. You need to load poetry (I gave up using regular venvs for poetry).
1. [**About poetry**](https://python-poetry.org/)
2. [**Installation Doc**](https://python-poetry.org/docs/)
    * OSX/Linux: `curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -`
    * Windows PS: `(Invoke-WebRequest -Uri https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py -UseBasicParsing).Content | python -`
DEPS installetion: `poetry install`
VENV activation: `poetry shell` or `source venv/bin/activate.bat`

## Usage

`./runtool.py [-h] [--token [TOKEN]] -targets [TARGETS] [--paths [PATHS]] [--resolve [BOOL]]` where:
1. token - BEREAR token. But you can also try without token (anon users are common issue!)
2. targets - targets that could be resolved. This targets could be scanned on open ports and vulnerabilities.
3. paths - API paths for RHOCP (OpenShift).
4. resolve - try to resolve DNS into different addresses.

# Follow me on telegram!
**[Here](https://t.me/r1v3ns_life) I am talking about security of different products.**
