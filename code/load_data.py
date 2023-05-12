import re
import os
import json
import logging
from collections import defaultdict
import argparse

logger = logging.getLogger(__name__)
BASEDIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")

class BSDataLoader:
    def __init__(self, func, local_vars, args, decompiler) -> None:
        self.function = func
        self.local_vars = local_vars
        self.args = args
        self.decompiler = decompiler
    

class IDALoader:
    def __init__(self) -> None:
        pass
        

class GhidraLoader:
    def __init__(self) -> None:
        pass


#
# Raw IDA decompiled code pre-processing
#


def rm_comments(func):

    cm_regex = r'// .*'
    cm_func = re.sub(cm_regex, ' ', func)

    return cm_func


def find_dwaf_decompiler_vars(all_vars):

    dwarf, ida_gen = [], []
    for var in all_vars:
        if re.search(r"v\d+", var) or re.search(r"a\d+", var):
            #print(re.search(r"v\d+", var))
            ida_gen.append(var)
        else:
            dwarf.append(var)
    return dwarf, ida_gen


def random_str(n: int):
    import random, string
    charset = string.ascii_lowercase + string.digits
    return "varid_" + "".join([random.choice(charset) for _ in range(n)])


def preprocess_binsync_raw_code(func: str, local_vars: list, func_args: list):

    # rm comments
    func = rm_comments(func)
    
    all_vars =  func_args + local_vars
    print(f"all vars: {all_vars}")

    # categorize variables
    dwarf, ida_gen = find_dwaf_decompiler_vars(all_vars)
    print(f"dwarf: {dwarf} \nida_gen: {ida_gen}")
    
    # pre-process variables and replace them with "@@var_name@@random_id@@"
    varname2token = {}
    for varname in all_vars:
        varname2token[varname] = f"@@{varname}@@{random_str(6)}@@"
    
    new_func = func
    # this is a poor man's parser lol
    allowed_prefixes = [" ", "&", "(", "*", "++", "--", ")"]
    allowed_suffixes = [" ", ")", ",", ";", "["]
    for varname, newname in varname2token.items():
        for p in allowed_prefixes:
            for s in allowed_suffixes:
                new_func = new_func.replace(f"{p}{varname}{s}", f"{p}{newname}{s}")
    return new_func, func_args

def replace_varnames_in_code(processed_code: str, func_args, names, origins, predict_for_decompiler_generated_vars: bool=False) -> str:
    # import ipdb; ipdb.set_trace()
    # collect all variable name holders
    all_holders = re.findall(r"@@[^\s@]+@@[^\s@]+@@", processed_code)

    varid2names = defaultdict(list)
    varid2original_name = {}
    varid2allnames = defaultdict(list)
    varid2origin = {}
    funcargs_in_varid = set()
    varid2holder = {}
    orig_name_2_popular_name = {}
    print(len(all_holders), "\n", len(names))
    
    if len(all_holders) != len(names):
        return "// Error: Unexpected number of variable name holders versus variable names."
    if len(all_holders) != len(origins):
        return "// Error: Unexpected number of variable name holders versus variable origins."
    for i, holder in enumerate(all_holders):
        original_name, varid = holder.split("@@")[1:3]
        varid2names[varid].append(names[i]["pred_name"])
        varid2allnames[varid] += [ item["pred_name"] for item in names[i]["top-k"] ]
        varid2holder[varid] = holder
        if varid in varid2origin and varid2origin[varid] == "Dwarf":
            varid2origin[varid] = origins[i]["variable_type"]
        elif varid not in varid2origin:
            varid2origin[varid] = origins[i]["variable_type"]
        if original_name in func_args:
            funcargs_in_varid.add(varid)
        varid2original_name[varid] = original_name

    # majority vote
    result_code = processed_code
    used_names = set()
    for varid, names in varid2names.items():
        names2count = defaultdict(int)
        for name in names:
            if name not in used_names:
                names2count[name] += 1
        if names2count:
            count2name = dict((v, k) for (k, v) in names2count.items())
            popular_name = count2name[max(count2name.keys())]
            used_names.add(popular_name)
        else:
            # fall back to all names
            names2count = defaultdict(int)
            for name in varid2allnames[varid]:
                if name not in used_names:
                    names2count[name] += 1
            if names2count:
                count2name = dict((v, k) for (k, v) in names2count.items())
                popular_name = count2name[max(count2name.keys())]
                used_names.add(popular_name)
            else:
                # give up
                popular_name = "#FAILED#"

        # origin information
        if varid not in funcargs_in_varid and varid2origin[varid] == "Decompiler":
            if not predict_for_decompiler_generated_vars:
                popular_name = varid2original_name[varid]
            popular_name += " /*decompiler*/"
        result_code = result_code.replace(varid2holder[varid], popular_name)
        
        # original name to popular name
        orig_name_2_popular_name[varid2original_name[varid]] = popular_name
    return result_code, orig_name_2_popular_name




BINSYNC_FUNCTIONS = []
binsync_funcs_path = os.path.join(BASEDIR, "data", "binsync_data.json")
if os.path.isfile(binsync_funcs_path):
    with open(binsync_funcs_path, "r") as f:
        BINSYNC_FUNCTIONS = f.readlines()