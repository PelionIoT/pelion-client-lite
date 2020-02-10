TEST_MODULES = ./test_modules
TEST_MODULE_MBED_TLS = $(TEST_MODULES)/mbedtls

.PHONY: build
build:
	if [ ! -d $(TEST_MODULES) ]; \
		then mkdir $(TEST_MODULES); \
	fi;

	if [ ! -d $(TEST_MODULE_MBED_TLS) ]; then \
		git clone --depth 1 git@github.com:ARMmbed/mbedtls.git $(TEST_MODULE_MBED_TLS); \
		cd $(TEST_MODULE_MBED_TLS); \
		git submodule update --init crypto; \
	fi;

	cd ./test && cmake .
	cd ./test && make

.PHONY: clean
clean:
	cd ./test && make clean

.PHONY: doxygen
doxygen:
	cd docs/diagrams; plantuml *.uml
	doxygen docs/doxygen.conf
