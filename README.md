# VAR Model
Predict variable names for your favorite decompiler with the Variable Annotation Recommendation Model! 
Model available for IDA. Ghidra coming soon!

## Setup
```bash
git clone git@github.com:binsync/varmodel.git
pip3 install ./varmodel
```

This requires internet connection, as it will download the 400mb model during the install process. If you don't have
400mb of space, don't install this! 

## Usage
If you want a GUI experience, install this library then go over to BinSync and use in the `Utils` tab. 
To use it programmatically, you must reference the API class:

```python
from varmodel import VariableRenamingAPI

api = VariableRenamingAPI(decompiler="ida")
api.predict_variable_names(function_text, binsync_function)
```
Where `function_text` is the decompilation text and `binsync_function` is the `Function` you plan to have variables
renamed for. See the testcase in `tests` for an expanded use example. 

