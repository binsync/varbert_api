# VarBERT
Predict variable names for your favorite decompiler. 

Model available for IDA. Ghidra coming soon!

## Setup
```bash
git clone git@github.com:binsync/varbert.git
pip3 install ./varbert
```

## Usage
If you want a GUI experience, install this library then go over to BinSync and use in the `Utils` tab. 
To use it programmatically, you must reference the API class:
```python
from AVAR import VariableRenamingAPI
api = VariableRenamingAPI(decompiler="ida")
api.predict_variable_names(function_text, binsync_function)
```
Where `function_text` is the decompilation text and `binsync_function` is the `Function` you plan to have variables
renamed for. See the testcase in `tests` for an expanded use example. 

