import re
import os
import json
import logging
from collections import defaultdict
import argparse
import random, string

logger = logging.getLogger(__name__)
BASEDIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")

class BSDataLoader:
    def __init__(self, raw_code) -> None:
        self.raw_code = raw_code
        self.local_vars = None
        self.func_args = None
       
        #TODO: update this to interact with binsync
    
    def rm_comments(self):
        cm_regex = r'// .*'
        self.raw_code = re.sub(cm_regex, '', self.raw_code)

    def random_str(self, n: int):        
        charset = string.ascii_lowercase + string.digits
        return "varid_" + "".join([random.choice(charset) for _ in range(n)])


    def find_local_vars(self, lines):
        # use regex
        regex = r"(\w+\d{0,6});"
        res = re.findall(regex, lines)
        return res

    def find_func_args(self, lines):
        all_args = []
        # https://stackoverflow.com/questions/476173/regex-to-pull-out-c-function-prototype-declarations
        regex = r'^([\w\*]+( )*?){2,}\(([^!@#$+%^;]+?)\)(?!\s*;)'
        res = re.search(regex, lines)
        if res:
            tmp_args = res.group(3).split(',')
            for ta in tmp_args:
                all_args.append(ta.split(' ')[-1].strip('*'))
        return all_args

    def preprocess_ida_raw_code(self):
        # rm comments
        self.rm_comments()
        func_sign = self.raw_code.split('{')[0]
        func_body = '{'.join(self.raw_code.split('{')[1:])

        # find variables
        varlines_bodylines = func_body.strip("\n").split('\n\n')
        if len(varlines_bodylines) >= 2:
            var_dec_lines = varlines_bodylines[0]
            self.local_vars = self.find_local_vars(var_dec_lines)
        else:
            self.local_vars = []

        # find arg
        self.func_args = self.find_func_args(func_sign)
        all_vars = self.func_args + self.local_vars

        # pre-process variables and replace them with "@@var_name@@random_id@@"
        varname2token = {}
        for varname in all_vars:
            varname2token[varname] = f"@@{varname}@@{self.random_str(6)}@@"
        new_func = self.raw_code
    
        # this is a poor man's parser lol
        allowed_prefixes = [" ", "&", "(", "*", "++", "--", ")"]
        allowed_suffixes = [" ", ")", ",", ";", "["]
        for varname, newname in varname2token.items():
            for p in allowed_prefixes:
                for s in allowed_suffixes:
                    new_func = new_func.replace(f"{p}{varname}{s}", f"{p}{newname}{s}")
        
        return new_func, self.func_args

    def preprocess_binsync_raw_code(self):

        # rm comments - not sure if code from binsync has them. This impacts the parsing hence inference
        self.rm_comments()
        
        # pre-process variables and replace them with "@@var_name@@random_id@@"
        all_vars =  self.func_args + self.local_vars
        varname2token = {}
        for varname in all_vars:
            varname2token[varname] = f"@@{varname}@@{self.random_str(6)}@@"
        
        new_func = self.raw_code
        # this is a poor man's parser lol
        allowed_prefixes = [" ", "&", "(", "*", "++", "--", ")"]
        allowed_suffixes = [" ", ")", ",", ";", "["]
        for varname, newname in varname2token.items():
            for p in allowed_prefixes:
                for s in allowed_suffixes:
                    new_func = new_func.replace(f"{p}{varname}{s}", f"{p}{newname}{s}")
        return new_func, self.func_args

    def replace_varnames_in_code(self, processed_code: str, func_args, names, origins, predict_for_decompiler_generated_vars: bool=False) -> str:

        # collect all variable name holders
        all_holders = re.findall(r"@@[^\s@]+@@[^\s@]+@@", processed_code)

        varid2names = defaultdict(list)
        varid2original_name = {}
        varid2allnames = defaultdict(list)
        varid2origin = {}
        funcargs_in_varid = set()
        varid2holder = {}
        orig_name_2_popular_name = {}
        
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



# Mostly we'll need to implement IDA and Ghidra due to parsing for inference!

class IDALoader(BSDataLoader):
    def __init__(self):
        super().__init__()
        
        

class GhidraLoader(BSDataLoader):
    def __init__(self):
        super().__init__()

