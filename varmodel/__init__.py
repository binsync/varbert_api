__version__ = "1.3.0"

import importlib.resources
import tarfile
from pathlib import Path
import urllib.request
import hashlib
import math
import platform
from typing import Optional, List
import shutil

from tqdm import tqdm
from yodalib.api import DecompilerInterface
from yodalib.decompilers import GHIDRA_DECOMPILER, IDA_DECOMPILER

# initialize logging for the entire project
import logging
logging.getLogger("varmodel").addHandler(logging.NullHandler())
from .logger import Loggers
loggers = Loggers()
del Loggers

from .api import VariableRenamingAPI

MODELS_PATH = Path(Path(str(importlib.resources.files("varmodel"))) / "models").absolute()
SUPPORTED_MODELS = {GHIDRA_DECOMPILER, IDA_DECOMPILER}
MODEL_FOLDER = "DECOMPILER-OPT-Function"
# all models are found here: https://www.dropbox.com/scl/fo/socl7rd5lsv926whylqpn/h?rlkey=i0x74bdipj41hys5rorflxawo
MODEL_URLS = {
    # function based models:
    f"{GHIDRA_DECOMPILER}-O0": "https://www.dropbox.com/scl/fi/8xsmmlzypd45icn8csk6y/Ghidra-O0-Function.tar.gz?rlkey=1b92b9ejktoyewjztvo3ns8q1&dl=1",
    f"{IDA_DECOMPILER}-O0": "https://www.dropbox.com/scl/fi/dmmfqqwvwhkswiv48ltfs/IDA-O0-Function.tar.gz?rlkey=3unxmiydbm5si3n7jh5r43qjp&dl=1",
    f"{GHIDRA_DECOMPILER}-O2": "https://www.dropbox.com/scl/fi/x5ci28s0aw3i852kg9w1j/Ghidra-O2-Function.tar.gz?rlkey=wpe08afvxelcblgcqndrxmvtm&dl=1",
    f"{IDA_DECOMPILER}-O2": "https://www.dropbox.com/scl/fi/ku26eebbwvug5fu2pc4ek/IDA-O2-Function.tar.gz?rlkey=edlri604hhuohh8n5d7d02tnd&dl=1",
    # binary based models:
    #f"{GHIDRA_DECOMPILER}-O2": "https://www.dropbox.com/scl/fi/nbk5b068z6ffsdl0kgbuw/Ghidra-O2-Binary.tar.gz?rlkey=m83iit4jh5fg6icl5cf2z3yhq&dl=1",
    #f"{IDA_DECOMPILER}-O2": "https://www.dropbox.com/scl/fi/vk0ybwu4uoru4fl61yztw/IDA-O2-Binary.tar.gz?rlkey=9rt8js8qrhkqp2cvvttxrlwd2&dl=1",
}

_l = logging.getLogger(__name__)


def install_model(decompiler, opt_level="O0", reinstall=False):
    # check if the model exists
    decompiler_model = MODELS_PATH / decompiler
    if decompiler_model.exists():
        if reinstall:
            shutil.rmtree(decompiler_model)
        else:
            _l.info(f"Model for {decompiler} already exists. Skipping download.")
            return

    # saved models on the remote side have some messed up names, so we have to do some
    # string matching here to make sure we download and move the correct stuff
    compliant_decompiler_name = decompiler
    if decompiler == GHIDRA_DECOMPILER:
        decompiler = "Ghidra"
    elif decompiler == IDA_DECOMPILER:
        decompiler = "IDA"

    dl_model_folder = MODELS_PATH / Path(MODEL_FOLDER.replace("DECOMPILER", decompiler).replace("OPT", opt_level))
    url = MODEL_URLS[f"{compliant_decompiler_name}-{opt_level}"]
    _l.info(f"Downloading model for {compliant_decompiler_name} now...")
    tar_file_path = _download_file(url, MODELS_PATH / f"model.tar.gz")
    with tarfile.open(tar_file_path, "r:gz") as tar:
        tar.extractall(path=MODELS_PATH)

    # move the model folder to be in a compliant form
    dl_model_folder.rename(MODELS_PATH / compliant_decompiler_name)
    # delete the old tar
    tar_file_path.unlink()


def _download_file(url: str, save_location: Path, verify_hash=False) -> Path:
    # XXX: hacked code for non-ssl verification
    if platform.system() == "Darwin":
        import ssl
        ssl._create_default_https_context = ssl._create_unverified_context

    with urllib.request.urlopen(url) as response:
        total_size = response.length
        if response.status != 200:
            raise Exception(f"HTTP error {response.status}: {response.reason}")

        hasher = hashlib.md5()
        chunk_size = 8192
        mb_size = int(total_size / 1000000)
        with open(save_location, 'wb') as f:
            for _ in tqdm(range(math.ceil(total_size / chunk_size)), desc=f"Downloading model ~{mb_size} MB..."):
                chunk = response.read(chunk_size)
                hasher.update(chunk)
                if not chunk:
                    break

                f.write(chunk)

        # hash for extra security
        #download_hash = hasher.hexdigest()
        #if verify_hash and download_hash != JOERN_ZIP_HASH:
        #    raise Exception(f"Files corrupted in download: {download_hash} != {JOERN_ZIP_HASH}")

    return save_location


def predict_for_functions(func_addrs: Optional[List[int]] = None, decompiler: Optional[str] = None):
    dec_interface = DecompilerInterface.discover_interface(force_decompiler=decompiler)
    varbert_api = VariableRenamingAPI(decompiler_interface=dec_interface)
    func_addrs = func_addrs if func_addrs else dec_interface.functions

    # grab real functions, which require decompilation, and predict names for them
    total_suggested_funcs = 0
    total_suggested_vars = 0
    for function_addr in tqdm(func_addrs, desc="Predicting names for functions..."):
        # functions can be both non-existent and non-decompilable
        try:
            function = dec_interface.functions[function_addr]
        except Exception:
            continue

        old_to_new_names, new_text = varbert_api.predict_variable_names(function)
        if old_to_new_names:
            total_suggested_funcs += 1
            total_suggested_vars += len(old_to_new_names)
            dec_interface.rename_local_variables_by_names(function, old_to_new_names)

    _l.info(f"Suggested names for {total_suggested_vars} variables in {total_suggested_funcs} functions.")
    # make sure things are destroyed
    del varbert_api, dec_interface

