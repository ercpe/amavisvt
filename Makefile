TARGET?=tests

VERSION := $(shell grep -Po '"(.*)"' amavisvt/__init__.py | sed -e 's/"//g')

test_default_python:
	PYTHONPATH="." python -m pytest tests/ --junit-xml testresults.xml -rxsw -v

test_py2:
	@echo Executing test with python2
	PYTHONPATH="." python2 -m pytest tests/ --junit-xml testresults.xml -rxsw -v

test_py3:
	@echo Executing test with python3
	PYTHONPATH="." python3 -m pytest tests/ --junit-xml testresults.xml -rxsw -v

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
	coverage xml -i
	coverage report -m

sonar:
	/usr/local/bin/sonar-scanner/bin/sonar-scanner -Dsonar.projectVersion=$(VERSION)

clean:
	find -name "*.py?" -delete
	rm -f coverage.xml
	rm -f testresults.xml
	rm -fr htmlcov dist amavisvt.egg-info

fix:
	find -name "*.py" -exec sed -i -r 's/^\s+$//g' {} +

travis: compile compile_optimized test_default_python coverage
jenkins: travis sonar
