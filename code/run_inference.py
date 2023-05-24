import re
import os
import json
import logging
from collections import defaultdict
import argparse
import random, string
import pprint 
import torch
import torch.nn as nn
from torch.nn import CrossEntropyLoss

from load_data import BSDataLoader
from varbert_model import varec_init, process

logger = logging.getLogger(__name__)
BASEDIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")

MODELS = {
    "ida": "model_ida_O0",
    # "ghidra": "model_ghidra_O0"
}


def init_model(args):

    decompiler = args.decompiler
    model_name = MODELS[decompiler]
    print(BASEDIR)
  
    # model initialization
    model_dir = os.path.join(BASEDIR,  "models", MODELS[decompiler])
    if not os.path.isdir(model_dir):
        return {f"Model {decompiler} does not exist on the file system."}

    g_model, g_tokenizer, g_device = varec_init(model_dir)
    g_model.to(g_device)
    if torch.cuda.is_available():
        g_model.half()

    return g_model, g_tokenizer, g_device


def binsync_predict(model, tokenizer, device, decompilation, Function):

    bsloader = BSDataLoader(
        decompilation,
        Function.stack_vars,
        Function.args
    )

    processed_code, func_args = bsloader.preprocess_binsync_raw_code()
    scores, score_origins = process(processed_code, model, tokenizer, device)
    if scores is None:
        scores = "Unparsable code or input exceeding maximum length"
    predicted_code, orig_name_2_popular_name = bsloader.replace_varnames_in_code(processed_code, func_args, scores, score_origins,
                                            predict_for_decompiler_generated_vars=False)
    return orig_name_2_popular_name

    

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--decompiler", help="Decompiler name to predict var names")
    parser.add_argument("--all", help="Predict variable names for all variables", action="store_true", default=False)
    args = parser.parse_args()
    init_model(args)
    binsync_predict()
   
 