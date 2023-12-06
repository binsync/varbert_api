import unittest
import sys
from typing import Dict

from varbert import VariableRenamingAPI
from yodalib.data import Function, FunctionArgument, FunctionHeader, StackVariable


def function_with_new_names(function: Function, new_names: Dict[str, str]):
    new_func: Function = function.copy()
    for old_name, new_name in new_names.items():
        for _, arg in new_func.args.items():
            if arg.name == old_name:
                arg.name = new_name

        for _, svar in new_func.stack_vars.items():
            if svar.name == old_name:
                svar.name = new_name

    return new_func


class TestBinSyncRenaming(unittest.TestCase):
    def test_renaming(self):
        api = VariableRenamingAPI(use_decompiler=False, decompiler_name="ida")

        # testing text
        function_text = "__int64 __fastcall sub_5E007(__int64 a1, __int64 a2, const char *a3)\n{\n  __int64 v3; // rcx\n  __int64 v4; // r8\n  __int64 v5; // r9\n  unsigned int v7; // [rsp+20h] [rbp-10h]\n  int v8; // [rsp+24h] [rbp-Ch]\n  __int64 v9; // [rsp+28h] [rbp-8h]\n\n  v9 = qword_246250;\n  v7 = 0;\n  v8 = atoi(a3);\n  if ( v8 >= 0 )\n  {\n    while ( v9 )\n    {\n      *(v9 + 3240) = v8;\n      v9 = *(v9 + 21664);\n      ++v7;\n    }\n    if ( a2 )\n      sub_33178(\n        4,\n        \"WARN: [%s] plugin name not supported for key 'telemetry_dump_kafka_topic_rr'. Globalized.\\n\",\n        a1,\n        v3,\n        v4,\n        v5);\n    return v7;\n  }\n  else\n  {\n    sub_33178(4, \"WARN: [%s] 'telemetry_dump_kafka_topic_rr' has to be >= 0.\\n\", a1, v3, v4, v5);\n    return 0xFFFFFFFFLL;\n  }\n}\n// 5E064: variable 'v3' is possibly undefined\n// 5E064: variable 'v4' is possibly undefined\n// 5E064: variable 'v5' is possibly undefined\n// 246250: using guessed type __int64 qword_246250;\n"
        svar_name_data = ["v3", "v4", "v5", "v7", "v8", "v9"]
        args_name_data = ["a1", "a2", "a3"]

        # WARNING: the offsets that these stack variables have as BinSync objects are not real and are only for this testcase
        function = Function(0xdead, 0x1337, header=FunctionHeader("sub_5E007", 0xdead, args={}), stack_vars={})
        for i, name in enumerate(svar_name_data):
            function.stack_vars[i] = StackVariable(i, name, None, 8, function.addr)
        for i, name in enumerate(args_name_data):
            function.args[i] = FunctionArgument(i, name, None, 8)

        new_names, _ = api.predict_variable_names(function, decompilation_text=function_text, use_decompiler=False)
        new_function = function_with_new_names(function, new_names)

        assert new_function.args[0] != function.args[0]
        assert new_function.args[1] != function.args[1]
        assert new_function.args[2] != function.args[2]

        assert new_function.stack_vars[3] != function.stack_vars[3]

    def test_renaming_1(self):
        api = VariableRenamingAPI(use_decompiler=False, decompiler_name="ida")

        # testing text
        function_text = "_int64 __fastcall main(int a1, char **a2, char **a3)\n{\n  _BOOL4 v4; // [rsp+1Ch] [rbp-24h] BYREF\n  char v5[16]; // [rsp+20h] [rbp-20h] BYREF\n  char buf[16]; // [rsp+30h] [rbp-10h] BYREF\n\n  buf[8] = 0;\n  v5[8] = 0;\n  puts(\"Username: \");\n  read(0, buf, 8uLL);\n  read(0, &v4, 1uLL);\n  puts(\"Password: \");\n  read(0, v5, 8uLL);\n  read(0, &v4, 1uLL);\n  v4 = sub_400664(buf, v5);\n  if ( !v4 )\n    sub_4006FD();\n  return sub_4006ED(buf);\n}\n"
        svar_name_data = ['v4', 'v5', 'buf']
        args_name_data = ["a1", "a2", "a3"]

        # WARNING: the offsets that these stack variables have as BinSync objects are not real and are only for this testcase
        function = Function(0xdead, 0x1337, header=FunctionHeader("main", 0xdead, args={}), stack_vars={})
        for i, name in enumerate(svar_name_data):
            function.stack_vars[i] = StackVariable(i, name, None, 8, function.addr)
        for i, name in enumerate(args_name_data):
            function.args[i] = FunctionArgument(i, name, None, 8)

        new_names, _ = api.predict_variable_names(function, decompilation_text=function_text, use_decompiler=False)
        new_function = function_with_new_names(function, new_names)

        assert new_function.args[0] != function.args[0]
        assert new_function.args[1] != function.args[1]
        assert new_function.args[2] != function.args[2]

        assert new_function.stack_vars[1] != function.stack_vars[1]
        assert new_function.stack_vars[2] != function.stack_vars[2]
    def test_renaming_2(self):
        api = VariableRenamingAPI(use_decompiler=False, decompiler_name="ida")

        # testing text
        function_text = '''__int64 __fastcall main(int a1, char **a2, char **a3, char a4)
        {
        const char *v5; // rbp

        if ( a1 != 2 )
            return 0LL;
        sub_2B30(*a2);
        setlocale(6, "");
        bindtextdomain("coreutils", "/usr/share/locale");
        textdomain("coreutils");
        sub_5550(sub_2A80);
        v5 = a2[1];
        if ( !strcmp(v5, "--help") )
            sub_2700(0);
        if ( !strcmp(v5, "--version") )
            sub_4DC0(stdout, "true", &unk_6084, Version, "Jim Meyering", 0, a4);
        return 0LL;
        }
        '''
        svar_name_data = ['v5']
        args_name_data = ["a1", "a2", "a3", "a4"]
        # WARNING: the offsets that these stack variables have as BinSync objects are not real and are only for this testcase
        function = Function(0xdead, 0x1337, header=FunctionHeader("main", 0xdead, args={}), stack_vars={})
        for i, name in enumerate(svar_name_data):
            function.stack_vars[i] = StackVariable(i, name, None, 8, function.addr)
        for i, name in enumerate(args_name_data):
            function.args[i] = FunctionArgument(i, name, None, 8)

        new_names, _ = api.predict_variable_names(function, decompilation_text=function_text, use_decompiler=False)
        new_function = function_with_new_names(function, new_names)

        assert new_function.args[0] != function.args[0]
        assert new_function.args[1] != function.args[1]
        assert new_function.args[2] != function.args[2]
        assert new_function.args[3] != function.args[3]

    def test_renaming_3(self):
        api = VariableRenamingAPI(use_decompiler=False, decompiler_name="ida")

        # testing text
        function_text = '''  __int64 __fastcall sub_4760(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
        {
        __int128 v6[2]; // [rsp+0h] [rbp-48h] BYREF
        __m128i si128; // [rsp+20h] [rbp-28h]
        __int64 v8; // [rsp+30h] [rbp-18h]
        unsigned __int64 v9; // [rsp+38h] [rbp-10h]

        v9 = __readfsqword(0x28u);
        v6[0] = _mm_load_si128(&xmmword_A1E0);
        v8 = qword_A210;
        LODWORD(v6[0]) = 10;
        v6[1] = _mm_load_si128(&xmmword_A1F0);
        si128 = _mm_load_si128(&xmmword_A200);
        if ( !a2 || !a3 )
            abort();
        si128.m128i_i64[1] = a2;
        v8 = a3;
        return sub_3F20(a1, a4, a5, v6);
        }'''
        svar_name_data = ['v6', "s128", "v8", "v9"]
        args_name_data = ["a1", "a2", "a3", "a4", "a5"]
        # WARNING: the offsets that these stack variables have as BinSync objects are not real and are only for this testcase
        function = Function(0xdead, 0x1337, header=FunctionHeader("sub_4760", 0xdead, args={}), stack_vars={})
        for i, name in enumerate(svar_name_data):
            function.stack_vars[i] = StackVariable(i, name, None, 8, function.addr)
        for i, name in enumerate(args_name_data):
            function.args[i] = FunctionArgument(i, name, None, 8)

        new_names, _ = api.predict_variable_names(function, decompilation_text=function_text, use_decompiler=False)
        new_function = function_with_new_names(function, new_names)

        assert new_function.args[0] != function.args[0]
        assert new_function.args[1] != function.args[1]
        assert new_function.args[2] != function.args[2]
        assert new_function.args[3] != function.args[3]
        assert new_function.args[4] != function.args[4]

    def test_renaming_4(self):
        api = VariableRenamingAPI(use_decompiler=False, decompiler_name="ida")

        # testing text
        function_text =   '''__int64 __fastcall main(int a1, char **a2, char **a3)
        {
        char *v4; // r12
        char *v5; // rax
        char *v6; // rbp
        const char *v7; // r13
        const char *v8; // r13
        char *v9; // rax
        char *v10; // rax
        FILE *v11; // r12
        char *v12; // rax
        FILE *v13; // r12
        char *v14; // rax
        char *v15; // rax
        __int64 *v16; // rbp
        const char *v17; // rsi
        const char *v18; // r14
        char *v19; // rax
        char *v20; // rdi
        char *v21; // rax
        char *v22; // r12
        char *v23; // rax
        char *v24; // rax
        char *v25; // rdi
        char *v26; // rax
        FILE *v27; // rbp
        char *v28; // rax
        __int64 v29[21]; // [rsp+0h] [rbp-A8h] BYREF

        v29[15] = __readfsqword(0x28u);
        if ( a1 != 2 )
            return 0LL;
        v4 = *a2;
        if ( !*a2 )
        {
            fwrite("A NULL argv[0] was passed through an exec system call.\n", 1uLL, 0x37uLL, stderr);
            abort();
        }
        v5 = strrchr(v4, 47);
        v6 = v5;
        if ( v5 )
        {
            v7 = v5 + 1;
            if ( v5 + 1 - v4 > 6 && !strncmp(v5 - 6, "/.libs/", 7uLL) )
            {
            v4 = v7;
            if ( !strncmp(v7, "lt-", 3uLL) )
            {
                v4 = v6 + 4;
                program_invocation_short_name = v6 + 4;
            }
            }
        }
        qword_7028 = v4;
        program_invocation_name = v4;
        setlocale(6, "");
        bindtextdomain("coreutils", "/usr/share/locale");
        textdomain("coreutils");
        sub_39D0(sub_3390);
        v8 = a2[1];
        if ( !strcmp(v8, "--help") )
        {
            v9 = dcgettext(0LL, "Usage: %s [ignored command line arguments]\n  or:  %s OPTION\n", 5);
            __printf_chk(1LL, v9, v4, v4);
            v10 = dcgettext(0LL, "Exit with a status code indicating success.", 5);
            __printf_chk(1LL, "%s\n\n", v10);
            v11 = stdout;
            v12 = dcgettext(0LL, "      --help     display this help and exit\n", 5);
            fputs_unlocked(v12, v11);
            v13 = stdout;
            v14 = dcgettext(0LL, "      --version  output version information and exit\n", 5);
            fputs_unlocked(v14, v13);
            v15 = dcgettext(
                    0LL,
                    "\n"
                    "NOTE: your shell may have its own version of %s, which usually supersedes\n"
                    "the version described here.  Please refer to your shell's documentation\n"
                    "for details about the options it supports.\n",
                    5);
            __printf_chk(1LL, v15, "true");
            v29[2] = "coreutils";
            v29[1] = "test invocation";
            v16 = v29;
            v17 = "[";
            v29[3] = "Multi-call invocation";
            v29[6] = "sha256sum";
            v29[4] = "sha224sum";
            v29[8] = "sha384sum";
            v29[0] = "[";
            v29[5] = "sha2 utilities";
            v29[7] = "sha2 utilities";
            v29[9] = "sha2 utilities";
            v29[10] = "sha512sum";
            v29[11] = "sha2 utilities";
            v29[12] = 0LL;
            v29[13] = 0LL;
            do
            {
            if ( !strcmp("true", v17) )
                break;
            v17 = v16[2];
            v16 += 2;
            }
            while ( v17 );
            v18 = v16[1];
            if ( v18 )
            {
            v19 = dcgettext(0LL, "\n%s online help: <%s>\n", 5);
            __printf_chk(1LL, v19, &unk_4047, "https://www.gnu.org/software/coreutils/");
            v20 = setlocale(5, 0LL);
            if ( !v20 || !strncmp(v20, "en_", 3uLL) )
            {
        LABEL_19:
                v21 = dcgettext(0LL, "Full documentation <%s%s>\n", 5);
                v22 = " invocation";
                __printf_chk(1LL, v21, "https://www.gnu.org/software/coreutils/", "true");
                if ( v18 != "true" )
                v22 = "";
        LABEL_21:
                v23 = dcgettext(0LL, "or available locally via: info '(coreutils) %s%s'\n", 5);
                __printf_chk(1LL, v23, v18, v22);
                exit(0);
            }
            }
            else
            {
            v24 = dcgettext(0LL, "\n%s online help: <%s>\n", 5);
            __printf_chk(1LL, v24, &unk_4047, "https://www.gnu.org/software/coreutils/");
            v25 = setlocale(5, 0LL);
            if ( !v25 || !strncmp(v25, "en_", 3uLL) )
            {
                v26 = dcgettext(0LL, "Full documentation <%s%s>\n", 5);
                v18 = "true";
                __printf_chk(1LL, v26, "https://www.gnu.org/software/coreutils/", "true");
                v22 = " invocation";
                goto LABEL_21;
            }
            v18 = "true";
            }
            v27 = stdout;
            v28 = dcgettext(0LL, "Report any translation bugs to <https://translationproject.org/team/>\n", 5);
            fputs_unlocked(v28, v27);
            goto LABEL_19;
        }
        if ( !strcmp(v8, "--version") )
            sub_3410(stdout, v29[0]);
        return 0LL;
        }
        '''
        svar_name_data = ['v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14', 'v15', 'v16', 'v17', 'v18', 'v19',
                          'v20', 'v21', 'v22', 'v23', 'v24', 'v25', 'v26', 'v27', 'v28', 'v29']
        args_name_data = ["a1", "a2", "a3"]
        # WARNING: the offsets that these stack variables have as BinSync objects are not real and are only for this testcase
        function = Function(0xdead, 0x1337, header=FunctionHeader("sub_4760", 0xdead, args={}), stack_vars={})
        for i, name in enumerate(svar_name_data):
            function.stack_vars[i] = StackVariable(i, name, None, 8, function.addr)
        for i, name in enumerate(args_name_data):
            function.args[i] = FunctionArgument(i, name, None, 8)

        new_names, _ = api.predict_variable_names(function, decompilation_text=function_text, use_decompiler=False)
        assert new_names != {}


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
