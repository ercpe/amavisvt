TARGET?=tests

test_default_python:
	PYTHONPATH="." python -m pytest tests/ -v

test_py2:
	@echo Executing test with python2
	PYTHONPATH="." python2 -m pytest tests/ -v

test_py3:
	@echo Executing test with python3
	PYTHONPATH="." python3 -m pytest tests/ -v

test: test_py2 test_py3

compile:
	@echo Compiling python code
	python -m compileall amavisvt/

compile_optimized:
	@echo Compiling python code optimized
	python -O -m compileall amavisvt/

coverage:
	coverage erase
	PYTHONPATH="." coverage run --source='amavisvt' --branch -m py.test -qq tests/
	coverage xml
	coverage report -m

clean:
	find -name "*.py?" -delete

travis: compile compile_optimized test_default_python coverage
jenkins: travis
