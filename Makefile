TARGET?=test

VERSION := $(shell grep -Po '"(.*)"' amavisvt/__init__.py | sed -e 's/"//g')

test:
	@echo Executing test with python3
	PYTHONPATH="." python3 -m pytest tests/ --junit-xml testresults.xml -rxsw -v

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
	rm -f coverage.xml testresults.xml .coverage
	rm -fr htmlcov dist build .cache amavisvt.egg-info

travis: compile compile_optimized test_default_python coverage
jenkins: travis sonar
