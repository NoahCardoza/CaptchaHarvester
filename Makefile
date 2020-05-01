clean:
	rm -rf build/ dist/ *.egg-info

dist: setup.py harvester/__init__.py
	pipenv run python setup.py sdist

upload: clean dist
	pipenv run python -m twine upload dist/*


# privacy pass

clean-privacy-pass:
	rm -rf challenge-bypass-extension privacy-pass-extension

build-privacy-pass: clean-privacy-pass
	git clone https://github.com/privacypass/challenge-bypass-extension.git &&\
	cd challenge-bypass-extension &&\
	git submodule update --init &&\
	make install &&\
	make sjcl &&\
	make build &&\
	make test-all;
	cp -r challenge-bypass-extension/addon privacy-pass-extension

update-privacy-pass: build-privacy-pass
	git status
	@/bin/echo -n "Are you sure? [y/N] " && read ans && [ $${ans:-N} = y ]
	git add privacy-pass-extension
	git commit -m "updated privacy pass"
	
	
.PHONY: clean dist upload test clean-privacy-pass build-privacy-pass update-privacy-pass
