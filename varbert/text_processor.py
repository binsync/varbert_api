import re
import os
import logging
import time
from collections import defaultdict
import random, string
from typing import Optional, Dict, Tuple

from libbs.api import DecompilerInterface
from libbs.artifacts import Function

_l = logging.getLogger(__name__)
BASEDIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")


class DecompilationTextProcessor:
    def __init__(self, raw_code, func: Optional[Function] = None, decompiler: Optional[DecompilerInterface] = None):
        self.raw_code = raw_code
        self._decompiler = decompiler
        self._func = func

        # updated in process_code
        self.processed_code = raw_code
        # TODO: this actually needs to be disabled for now because Function does not handle register variables
        #self.local_vars = None if not func else list(sv.name for sv in func.stack_vars.values())
        self.local_vars = None
        self.func_args = None if not func else list(arg.name for arg in func.args.values())

        self._random_strings = self._generate_random_strings()
        self._preprocess_code()

    #
    # Utils
    #

    @staticmethod
    def _generate_random_strings(amt=200, str_len=6):
        random_srings = set()
        charset = string.ascii_lowercase + string.digits
        for _ in range(amt):
            rand_str = "varid_" + "".join([random.choice(charset) for _ in range(str_len)])
            random_srings.add(rand_str)

        return random_srings

    def _random_str(self):
        if not self._random_strings:
            self._random_strings = self._generate_random_strings()

        return self._random_strings.pop()

    def _tokenize_names(self, names, token="@@"):
        return {
            # @@varname@@random_id@@
            name: f"{token}{name}{token}{self._random_str()}{token}" for name in names
        }

    #
    # Text editing
    #

    def _remove_comments(self):
        # Replace single-line comments with a newline
        self.processed_code = re.sub(r'//.*', '', self.processed_code)
        # Replace multi-line comments with a single newline
        self.processed_code = re.sub(r'/\*.*?\*/', '', self.processed_code, flags=re.DOTALL)

    #
    # Text Processing
    #

    def _preprocess_code(self):
        if self._decompiler:
            self._process_code_with_decompiler()
        else:
            self._process_code_with_text()

    def _process_code_with_decompiler(self):
        # some decompilers dont allow the @@ symbol in the variable names
        # to deal with this we use a tmp one and replace it in post processing
        tmp_token = "VARBERT"

        # refresh the decompiled obj backend
        self._func.dec_obj = self._decompiler.get_decompilation_object(self._func)
        original_names = self._decompiler.local_variable_names(self._func)
        og_name_to_tokenized_name = self._tokenize_names(original_names, token=tmp_token)
        tokenized_name_to_og_name = {v: k for k, v in og_name_to_tokenized_name.items()}

        # replace all original names with tmp tokenized names
        self._decompiler.rename_local_variables_by_names(self._func, og_name_to_tokenized_name)
        # get the decomp, fix the tmp tokens
        tokenized_dec_text = self._decompiler.decompile(self._func.addr)
        tokenized_dec_text = tokenized_dec_text.replace(tmp_token, "@@")

        # revert to the original names in the decomp
        if self._decompiler.supports_undo:
            # XXX: possible race conditions here
            time.sleep(0.5)
            self._decompiler.undo()
        else:
            self._decompiler.rename_local_variables_by_names(self._func, tokenized_name_to_og_name)

        if not self.func_args:
            self.func_args = [arg.name for arg in self._func.args.values() if arg.name in original_names]
        if not self.local_vars:
            self.local_vars = [name for name in original_names if name not in self.func_args]

        self.processed_code = tokenized_dec_text
        if "@@" not in self.processed_code:
            _l.error("Decompiler did not tokenize any variable names.")
            return

        self._remove_comments()

    def _process_code_with_text(self):
        # rm comments
        self._remove_comments()
        func_sign = self.processed_code.split('{')[0]
        func_body = '{'.join(self.processed_code.split('{')[1:])

        # find variables
        if not self.local_vars:
            varlines_bodylines = func_body.strip("\n").split('\n\n')
            self.local_vars = self.find_local_vars(varlines_bodylines[0]) if len(varlines_bodylines) >= 2 else []

        # find args
        if not self.func_args:
            self.func_args = self.find_func_args(func_sign)

        all_vars = self.func_args + self.local_vars
        # pre-process variables and replace them with "@@var_name@@random_id@@"
        varname2token = self._tokenize_names(all_vars)

        # this is a poor man's parser lol
        allowed_prefixes = [" ", "&", ",", "(", "*", "++", "--", "!"]
        allowed_suffixes = [" ", ")", ",", ";", "[", "++", "--"]

        for varname, newname in varname2token.items():
            for p in allowed_prefixes:
                for s in allowed_suffixes:
                    self.processed_code = self.processed_code.replace(f"{p}{varname}{s}", f"{p}{newname}{s}")

    #
    # Dec-unaware utils
    #

    @staticmethod
    def find_local_vars(lines):
        local_vars = []
        # regex = r"(\w+(\[\d+\]|\d{0,6}));"
        regex = r"(\w+(\s?\[\d+\]|\d{0,6}));"  # works for both ida and ghidra
        matches = re.finditer(regex, lines)
        if matches:
            for m in matches:
                tmpvar = m.group(1)
                if not tmpvar:
                    continue
                lv = tmpvar.split('[')[0].strip()
                local_vars.append(lv)
        return local_vars

    @staticmethod
    def find_func_args(lines):
        all_args = []
        # https://stackoverflow.com/questions/476173/regex-to-pull-out-c-function-prototype-declarations
        # regex = r'^([\w\*]+( )*?){2,}\(([^!@#$+%^;]+?)\)(?!\s*;)'
        regex = r'\w+\s+(\w+)\s*\(([^)]*)\)'
        res = re.search(regex, lines)
        if res:
            tmp_args = res.group(2).split(',')
            for ta in tmp_args:
                all_args.append(ta.split(' ')[-1].strip('*').strip())
        return all_args

    @staticmethod
    def generate_popular_names(
        processed_code: str, func_args, names, origins, predict_for_decompiler_generated_vars: bool=False
    ) -> Tuple[Dict[str, str], str]:

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
            _l.warning("Unexpected number of variable name holders versus variable names.")
            return {}, ""
        if len(all_holders) != len(origins):
            _l.warning("Unexpected number of variable name holders versus variable origins.")
            return {}, ""
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
        renamed_code = processed_code
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
            renamed_code = renamed_code.replace(varid2holder[varid], popular_name)
            
            # original name to popular name
            orig_name_2_popular_name[varid2original_name[varid]] = popular_name

        return orig_name_2_popular_name, renamed_code
