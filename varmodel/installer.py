import textwrap

from varmodel import SUPPORTED_MODELS, install_model

from yodalib.plugin_installer import YODAPluginInstaller


class VarmodelPluginInstaller(YODAPluginInstaller):
    def display_prologue(self):
        print(textwrap.dedent(
            """
            Installing...
            
            ██    ██  █████  ██████  ███    ███  ██████  ██████  ███████ ██      
            ██    ██ ██   ██ ██   ██ ████  ████ ██    ██ ██   ██ ██      ██      
            ██    ██ ███████ ██████  ██ ████ ██ ██    ██ ██   ██ █████   ██      
             ██  ██  ██   ██ ██   ██ ██  ██  ██ ██    ██ ██   ██ ██      ██      
              ████   ██   ██ ██   ██ ██      ██  ██████  ██████  ███████ ███████
              
            A programming interface to the VarBERT Research project.
            """
        ))

    def display_epilogue(self):
        super().display_epilogue()
        self.info("We will now download VarBERT models for each decompiler you've installed.")
        for target in self._successful_installs:
            if target in SUPPORTED_MODELS:
                install_model(target, opt_level="O2")

        self.info("Install completed!")
