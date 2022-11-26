FROM fuzzers/atheris:2.0.7-python3.9

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git clang

RUN git clone https://github.com/intelxed/mbuild.git mbuild
ADD . /src

# Build
WORKDIR /src
RUN ./mfile.py --shared --compiler="clang" --extra-flags="-fsanitize=fuzzer-no-link" --extra-linkflags="-fsanitize=fuzzer-no-link"
WORKDIR /src/pyext
RUN ln -s ../obj/wkit xedkit
RUN rm /usr/bin/x86_64-linux-gnu-gcc && ln -s /usr/bin/clang /usr/bin/x86_64-linux-gnu-gcc
RUN CC="/usr/bin/clang" CFLAGS="-fsanitize=fuzzer-no-link" CXX="/usr/bin/clang++" CXXFLAGS="-fsanitize=fuzzer-no-link" python3 setup.py install

CMD LD_PRELOAD=/usr/local/lib/python3.9/dist-packages/ubsan_with_fuzzer.so LD_LIBRARY_PATH=/src/pyext/xedkit/lib/ /src/mayhem/fuzz_decode.py
