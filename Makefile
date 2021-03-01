SHELL := /bin/bash

.PHONY: test test37 test38 test39 mypy coverage

TOX := docker-compose run --rm app tox

test:
	$(TOX)


test37:
	$(TOX) -e py37

test38:
	$(TOX) -e py38

test39:
	$(TOX) -e py39

mypy:
	$(TOX) -e mypy

.coverage: ${SOURCES} ${TESTS}
	$(TOX) -e py38

coverage: .coverage
	docker-compose run --rm app coverage report

coverage.xml: .coverage
	docker-compose run --rm app coverage xml