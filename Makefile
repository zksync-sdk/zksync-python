SHELL := /bin/bash

.PHONY: test test37 test38 test39 mypy coverage

.buildts:
	python3 setup.py install

TOX := docker-compose run --rm app

test: | .buildts
	$(TOX)


test37: | .buildts
	$(TOX) -e py37

test38: | .buildts
	$(TOX) -e py38

test39: | .buildts
	$(TOX) -e py39

mypy: | .buildts
	$(TOX) -e mypy

.coverage: ${SOURCES} ${TESTS} | .buildts
	$(TOX) -e py38

coverage: .coverage
	docker-compose run --rm app coverage report

coverage.xml: .coverage
	docker-compose run --rm app coverage xml