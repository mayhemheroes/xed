FROM python:3.11-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git \
    clang \
    libfuzzer-19-dev \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

# Install atheris (builds against system libFuzzer)
RUN pip install atheris

RUN git clone https://github.com/intelxed/mbuild.git mbuild
ADD . /src

# Build xed shared library with fuzzer-no-link instrumentation
WORKDIR /src
RUN ./mfile.py --shared --compiler="clang" --extra-flags="-fsanitize=fuzzer-no-link" --extra-linkflags="-fsanitize=fuzzer-no-link"
WORKDIR /src/pyext
RUN ln -s ../obj/wkit xedkit
RUN rm -f /usr/bin/x86_64-linux-gnu-gcc && ln -s /usr/bin/clang /usr/bin/x86_64-linux-gnu-gcc
RUN CC="/usr/bin/clang" CFLAGS="-fsanitize=fuzzer-no-link" CXX="/usr/bin/clang++" CXXFLAGS="-fsanitize=fuzzer-no-link" python3 setup.py install

CMD LD_PRELOAD=$(python3 -c "import atheris, os; print(os.path.join(os.path.dirname(atheris.__file__), 'ubsan_with_fuzzer.so'))") LD_LIBRARY_PATH=/src/pyext/xedkit/lib/ /src/mayhem/fuzz_decode.py
