TARGET?=tests

test_default_python:
	PYTHONPATH=".:./src" python -m pytest tests/ -v

test_py2:
	@echo Executing test with python2
	PYTHONPATH=".:./src" python2 -m pytest tests/ -v

test_py3:
	@echo Executing test with python3
	PYTHONPATH=".:./src" python3 -m pytest tests/ -v

test: test_py2 test_py3

compile:
	@echo Compiling python code
	python -m compileall src/

compile_optimized:
	@echo Compiling python code optimized
	python -O -m compileall src/

coverage:
	coverage erase
	PYTHONPATH=".:./src" coverage run --source='src' --branch -m py.test -qq tests/
	coverage report -m

travis: compile compile_optimized test_default_python coverage
