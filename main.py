import string
import base64
import codecs
import os
import random
import sys
from time import time
import argparse
from textwrap import wrap
from lzma import compress
from marshal import dumps
from pystyle import *
from getpass import getpass
from requests import post
from random import choice as _choice, randint as _randint
from random import randint as r
import ast,astor
from sys import argv as _argv

from pprint import(
    pformat
)
def IntObfuscator(intObj):
	MultiNumList=[2,3,5,7,11,13]
	SepIntA=r(0,intObj)
	SepIntB=intObj-SepIntA
	SepIntC,SepIntD=r(0,SepIntA),r(0,SepIntB)
	SepIntA,SepIntB,SepIntC,SepIntD=str(SepIntA-SepIntC),str(SepIntB-SepIntD),str(SepIntC),str(SepIntD)
	RandListA,RandListB,RandListC=[r(0,600),MultiNumList[r(0,5)],MultiNumList[r(0,5)]],[r(0,600),MultiNumList[r(0,5)],MultiNumList[r(0,5)]],[r(0,600),MultiNumList[r(0,5)],MultiNumList[r(0,5)]]
	RandIntAa,RandIntBa,RandIntCa=str(RandListA[0]*RandListA[1])+"*"+str(RandListA[2]),str(RandListB[0]*RandListB[1])+"*"+str(RandListB[2]),str(RandListC[0]*RandListC[1])+"*"+str(RandListC[2])
	RandIntAb,RandIntBb,RandIntCb=str(RandListA[0]*RandListA[2])+"*"+str(RandListA[1]),str(RandListB[0]*RandListB[2])+"*"+str(RandListB[1]),str(RandListC[0]*RandListC[2])+"*"+str(RandListC[1])
	del RandListA,RandListB,RandListC
	result=SepIntA+"+"+RandIntAa+"+"+SepIntB+"-"+RandIntAb+"+"+RandIntBa+"+"+SepIntC+"-"+RandIntBb+"+"+RandIntCa+"+"+SepIntD+"-"+RandIntCb
	return result
def ObfuscateAllInt(pyCode):
	AstPyCode=ast.parse(pyCode)
	class IntReplacer(ast.NodeTransformer):
		def visit_Num(self, node):
			Value = IntObfuscator(node.n)
			return ast.copy_location(ast.parse(Value).body[0].value, node)
	Replacer=IntReplacer()
	result=astor.to_source(Replacer.visit(AstPyCode))
	del Replacer
	return result
class Obfuscator:
    def __init__(self, code, outpath):
        self.code = code.encode()
        self.outpath = outpath
        self.varlen = 3
        self.vars = {}

        self.marshal()
        self.encrypt1()
        self.encrypt2()
        self.finalize()
    
    def generate_emoji(self):
        emoji_start = '0001f601'
        emoji_end = '0001f64f'
        emoji_code = random.randint(int(emoji_start, 16), int(emoji_end, 16))
        emoji = chr(emoji_code)
        return emoji
    
    def generate_alhabet(self):
        alphabet = []
        for _ in range(10):
            alphabet.append(random.choice(self.generate_emoji()))
        return alphabet

    def IntObfuscator(self, intObj):
        MultiNumList=[2,3,5,7,11,13]
        SepIntA=r(0,intObj)
        SepIntB=intObj-SepIntA
        SepIntC,SepIntD=r(0,SepIntA),r(0,SepIntB)
        SepIntA,SepIntB,SepIntC,SepIntD=str(SepIntA-SepIntC),str(SepIntB-SepIntD),str(SepIntC),str(SepIntD)
        RandListA,RandListB,RandListC=[r(0,600),MultiNumList[r(0,5)],MultiNumList[r(0,5)]],[r(0,600),MultiNumList[r(0,5)],MultiNumList[r(0,5)]],[r(0,600),MultiNumList[r(0,5)],MultiNumList[r(0,5)]]
        RandIntAa,RandIntBa,RandIntCa=str(RandListA[0]*RandListA[1])+"*"+str(RandListA[2]),str(RandListB[0]*RandListB[1])+"*"+str(RandListB[2]),str(RandListC[0]*RandListC[1])+"*"+str(RandListC[2])
        RandIntAb,RandIntBb,RandIntCb=str(RandListA[0]*RandListA[2])+"*"+str(RandListA[1]),str(RandListB[0]*RandListB[2])+"*"+str(RandListB[1]),str(RandListC[0]*RandListC[2])+"*"+str(RandListC[1])
        del RandListA,RandListB,RandListC
        result=SepIntA+"+"+RandIntAa+"+"+SepIntB+"-"+RandIntAb+"+"+RandIntBa+"+"+SepIntC+"-"+RandIntBb+"+"+RandIntCa+"+"+SepIntD+"-"+RandIntCb
        return result
    
    def ObfuscateAllInt(pyCode):
        AstPyCode=ast.parse(pyCode)
        class IntReplacer(ast.NodeTransformer):
            def visit_Num(self, node):
                Value = self.IntObfuscator(node.n)
                return ast.copy_location(ast.parse(Value).body[0].value, node)
        Replacer=IntReplacer()
        result=astor.to_source(Replacer.visit(AstPyCode))
        del Replacer
        return result

    def encode_string(self, string, alphabet):
        d1 = dict(enumerate(alphabet))
        d2 = {v: k for k, v in d1.items()}
        return (
            'eval("".join(map(chr,[int("".join(str({}[i]) for i in x)) for x in "{}".split(" ")])))'.format(
                pformat(d2),
                " ".join("".join(d1[int(i)] for i in str(ord(ch))) for ch in string)
            )
        )

    def generate(self, name):
        res = self.vars.get(name)
        if res is None:
            res = "IKUZADEV_" + "_" + "".join(["0001f601" for _ in range(self.varlen)])
            self.varlen += 1
            self.vars[name] = res
        return res

    def encryptstring(self, string, config={}, func=False):
        b64 = list(b"base64")
        b64decode = list(b"b64decode")
        __import__ = config.get("__import__", "__import__")
        getattr = config.get("getattr", "getattr")
        bytes = config.get("bytes", "bytes")
        eval = config.get("eval", "eval")
        if not func:
            return f'{getattr}({__import__}({bytes}({b64}).decode()),{bytes}({b64decode}).decode())({bytes}({list(base64.b64encode(string.encode()))})).decode()'
        else:
            attrs = string.split(".")
            base = self.encryptstring(attrs[0], config)
            attrs = list(map(lambda x: self.encryptstring(x, config, False), attrs[1:]))
            newattr = ""
            for i, val in enumerate(attrs):
                if i == 0:
                    newattr = f'{getattr}({eval}({base}),{val})'
                else:
                    newattr = f'{getattr}({newattr},{val})'
            return newattr

    def encryptor(self, config):
        def func_(string, func=False):
            return self.encryptstring(string, config, func)
        return func_

    def compress(self):
        self.code = compress(self.code)

    def marshal(self):
        self.code = dumps(compile(self.code, "<string>", "exec"))

    def encrypt1(self):
        code = base64.b64encode(self.code).decode()
        partlen = int(len(code) / 4)
        code = wrap(code, partlen)
        print(self.code)
        var1 = self.generate("a")
        var2 = self.generate("b")
        var3 = self.generate("c")
        var4 = self.generate("d")
        init = [f'{var1}="{codecs.encode(code[0], "rot13")}"', f'{var2}="{code[1]}"', f'{var3}="{code[2][::-1]}"', f'{var4}="{code[3]}"']

        random.shuffle(init)
        init = ";".join(init)
        self.code = f'''{init};__import__({self.encryptstring("builtins")}).exec(__import__({self.encryptstring("marshal")}).loads(__import__({self.encryptstring("base64")}).b64decode(__import__({self.encryptstring("codecs")}).decode({var1}, __import__({self.encryptstring("base64")}).b64decode("{base64.b64encode(b'rot13').decode()}").decode())+{var2}+{var3}[::-1]+{var4})))'''.strip().encode()

    def encrypt2(self):
        self.compress()
        var1 = self.generate("e")
        var2 = self.generate("f")
        var3 = self.generate("g")
        var4 = self.generate("h")
        var5 = self.generate("i")
        var6 = self.generate("j")
        var7 = self.generate("k")
        var8 = self.generate("l")
        var9 = self.generate("m")

        conf = {
            "getattr" : var4,
            "eval" : var3,
            "__import__" : var8,
            "bytes" : var9
        }
        encryptstring = self.encryptor(conf)

        self.code = f'''
{var3} = eval({self.encryptstring("eval")});{var4} = {var3}({self.encryptstring("getattr")});{var8} = {var3}({self.encryptstring("__import__")});{var9} = {var3}({self.encryptstring("bytes")});{var5} = lambda {var7}: {var3}({encryptstring("compile")})({var7}, {encryptstring("<string>")}, {encryptstring("exec")});{var1} = {self.code}
{var2} = {encryptstring('__import__("builtins").list', func= True)}({var1})
try:
    {encryptstring('__import__("builtins").exec', func= True)}({var5}({encryptstring('__import__("lzma").decompress', func= True)}({var9}({var2})))) or {encryptstring('__import__("os")._exit', func= True)}(0)
except {encryptstring('__import__("lzma").LZMAError', func= True)}:...
'''.strip().encode()

    def encrypt3(self):
        self.compress()
        data = base64.b64encode(self.code)
        self.code = f'import base64, lzma; exec(compile(lzma.decompress(base64.b64decode({data})), "<string>", "exec"))'.encode()

    def finalize(self):
        build_folder = "build"
        if not os.path.exists(build_folder):
            os.makedirs(build_folder)

        out_file_path = os.path.join(build_folder, os.path.basename(self.outpath))
        with open(out_file_path, "w", encoding="utf-8") as file:
            self.code += b"\n # D5Studio.site"
            file.write(ObfuscateAllInt(self.code.decode()))

        print(f"Obfuscated file saved to: {out_file_path}")


def Main():
    file = input(f"Input Your File -> ").replace('"', '').replace("'", "")
    try:
        with open(file, mode='rb') as f:
            script = f.read().decode('utf-8')
        filename = file.split('\\')[-1]
    except:
        print("Invalid File!!")
    now = time()
    Obfuscator(script, f'obf-{filename}')
    now = round(time() - now, 2)
    print('\n')
    print(f"Obfuscation completed successfully in {now}s")

if __name__ == '__main__':
    try:
        Main()
    except KeyboardInterrupt:
        os.system("cls")
        print("Exit")
        exit()