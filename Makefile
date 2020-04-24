clean:
	rm -rf build/ dist/ *.egg-info

dist: setup.py harvester/__init__.py
	pipenv run python setup.py sdist

upload: clean dist
	pipenv run python -m twine upload dist/*

.PHONY: clean dist upload test
