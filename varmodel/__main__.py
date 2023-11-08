import argparse
import logging

from yodalib.decompilers import YODALIB_SUPPORTED_DECOMPILERS, GHIDRA_DECOMPILER


from varmodel import install_model, predict_for_functions
from varmodel.installer import VarmodelPluginInstaller


_l = logging.getLogger(__name__)


class Commands:
    PREDICT = "predict"
    INSTALL = "install"
    ALL_COMMANDS = [PREDICT, INSTALL]


def install(decompiler):
    VarmodelPluginInstaller().install()


def main():
    parser = argparse.ArgumentParser(description="""
    The Variable Renaming Model is a model that predicts variable names based on the decompiled code.
    This script is used either inside a decompiler or to spawn a decompiler. 
    """)
    parser.add_argument("cmd", type=str, choices=Commands.ALL_COMMANDS, help="Command to run")
    parser.add_argument("--decompiler", type=str, choices=YODALIB_SUPPORTED_DECOMPILERS, help="Decompiler to use")
    parser.add_argument("--functions", type=str, nargs="+", help="Functions to predict on")
    args = parser.parse_args()

    if args.cmd == Commands.INSTALL:
        install(args.decompiler)
    elif args.cmd == Commands.PREDICT:
        functions = args.functions
        if functions:
            functions = [int(func, 0) for func in args.functions]

        predict_for_functions(func_addrs=functions, decompiler=args.decompiler)


if __name__ == "__main__":
    main()