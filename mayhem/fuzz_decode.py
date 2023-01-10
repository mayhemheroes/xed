#!/usr/bin/env python3
import atheris
import sys

with atheris.instrument_imports():
    import xed

def build_fuzz_list(fdp: atheris.FuzzedDataProvider):
    """
    Builds a list with fuzzer-defined elements.
    :param fdp: FuzzedDataProvider object
    :param ty_queue: The current stack of types to be used for fuzzing
    :return: The list
    """
    elem_count = fdp.ConsumeIntInRange(1, 300)
    gen_list = []

    for _ in range(elem_count):
        elem = fdp.ConsumeInt(4)
        gen_list.append(elem)

    return gen_list


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    asm_source = build_fuzz_list(fdp)
    try:
        if fdp.ConsumeBool():
            xed.dis32(asm_source)
        else:
            xed.dis64(asm_source)
    except SystemError as e:
        if 'with an error' not in str(e):
            raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
