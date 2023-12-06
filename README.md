# VARModel
The Variable Annotation Recommendation Model (VARModel) is the Python library for the VarBERT research project.
Using VARModel, you can use our local model to predict variable names for your decompiled code.
Specialized models exist for IDA Pro and Ghidra, but can be used on any decompiler. 

<p align="center">
    <img src="./assets/varbert_no_background.png" style="width: 50%;" alt="DAILA context menu"/>
</p>

This project is for providing an API and CLI interface into the VarBERT models, but if you would like to use these
models directly in your decompiler, with an integrated UI, use the [DAILA](https://github.com/mahaloz/DAILA) project.
VARModel comes bundled with DAILA, so you do not need to install VARModel if you are using DAILA.

## Install 
```
pip3 install varmodel && varmodel --download-models
```

This will install the VARModel library and download the models to be stored inside the VARModel package.
You can optionally provide a decompiler name to `--download-models` to only download the models for that decompiler.

## Usage
VARModel can be used in three ways:
- From the CLI, directly on decompiled text (without an attached decompiler)
- As a scripting library 
- As a decompiler plugin (using [DALIA](https://github.com/mahaloz/DAILA)) 

To use VARModel directly on text, see the [tests.py](./tests/tests.py) file for examples. 
To use it as a decompiler plugin, follow the instructions below.

### Command Line (without running a decompiler)
Note that VARModel runs better when it is directly hooked up to a decompiler because it can use additional semantic information that the decompiler knows about the decompiled code.
However, we do have the ability to run VARModel without a running decompiler, only operating on the text from the command line.

Running the following will cause VARModel to read a function from standard input and output the function with predicted variable names to standard out:
```bash
varmodel --predict --decompiler ida
```

You can select different decompilers that will use different models that are trained on the different decompilers.
If you do not specify a decompiler, the default is IDA Pro.
As an example, you can also give no decompiler:
```bash 
 echo "__int64 sub_400664(char *a1,char *a2)\n {}" | varmodel -p
```

### Scripting
#### Without Decompiler
```python
from varmodel import VariableRenamingAPI
api = VariableRenamingAPI(decompiler_name="ida", use_decompiler=False)
new_names, new_code = api.predict_variable_names(decompilation_text="__int64 sub_400664(char *a1,char *a2)\n {}", use_decompiler=False)
print(new_code)
```

You can also find more examples in the [tests.py](./tests/tests.py) file.

#### Inside Decompiler
You can use VARModel as a scripting library inside your decompiler, utilizing LibBS.
```python
from varmodel import VariableRenamingAPI
from libbs.api import DecompilerInterface
dec = DecompilerInterface()
api = VariableRenamingAPI(decompiler_interface=dec)
for func_addr in dec.functions:
    new_names, new_code = api.predict_variable_names(function=dec.functions[func_addr])
    print(new_names)
```

### As a Decompiler Plugin
If you would like to use VARModel as a decompiler plugin, you can use [DAILA](https://github.com/mahaloz/DAILA).
You should follow the instructions on the DAILA repo to install DAILA, but it's generally as simple as:
```bash
pip3 install dailalib && daila --install
```

## Citing 
If you use VARModel in your research, please cite our paper:
```
```