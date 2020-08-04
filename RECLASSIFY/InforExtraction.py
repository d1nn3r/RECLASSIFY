#!/usr/bin/env python
#-*-coding:utf-8-*-
'''
Author: d1nn3r
'''
import json
import time
import re
import idautils
import idaapi
import idc
import sys
import struct

# vftable所在地址段
# Address segment where vftable is located
vftable_section_names = [".rodata",
	".data.rel.ro",
	".data.rel.ro.local",
	".rdata"]
# VTT所在地址段
# Address segment where VTT is located
VTT_section_names = [".rodata",
	".data.rel.ro",
	".data.rel.ro.local",
	".rdata"]
# vbtable所在地址段
# Address segment where vbtable is located
vbtable_section_names = [".rdata"]

# delete符号表
# delete() symbol list
delete_operations = ["??3@YAXPAX@Z",
	"??3@YAXPEAX_K@Z",
	"??3@YAXPEAX@Z",
	"j_??3@YAXPEAX_K@Z",
	"j_j_free",
	"j_free",
	"free",
	"j_j_free_0",
	"j_j_j_free_0",
	"j_free_0",
	"free_0",

	"__ZdlPv",
	"_ZdlPv"]
# new符号表
# new() symbol list 
new_operations = ["??2@YAPAXI@Z",
	"??2@YAPEAX_K@Z",
	"??2@YAPEAX@Z",
	"j_??2@YAPEAX_K@Z",
	"j_??_U@YAPEAX_K@Z",
	"malloc",
	"malloc_0",

	"__Znwm",
	"_Znwm"]

# 若开启RTTI则为True，默认False
# True if RTTI is turned on, default False
# TODO：通过RTTI恢复待实现
use_RTTI = False

# 纯虚函数地址
# Pure virtual function address
purecall_addr = 0

vftable_list = dict()
vbtable_list = dict()
vftables_addr = list()
delete_xref_list = list()
ctor_list = dict()
symbol_list = dict()

VTT_list = dict()

'''
获得RTTI地址

参数：
	vftable_addr: vftable地址
返回：
	rtti_addr: RTTI地址
'''

'''
Get RTTI address

Args:
	vftable_addr: vftable address
Return:
	rtti_addr: RTTI address
'''
# TODO：通过RTTI恢复待实现
def get_vftable_rtti(vftable_addr):
	pass

'''
寻找虚基类偏移

参数：
	ctor: 构造函数地址
	ins: 当前指令
	reg1: 
	reg2:
	digit:
返回：
	offset: 虚基类偏移
'''
def find_vbase_offset(ctor,ins,reg1,reg2,digit):
	func_start = idc.GetFunctionAttr(ins, idc.FUNCATTR_START)
	last_ins = idc.GetFunctionAttr(ins, idc.FUNCATTR_START)
	reverse_ins_list = list(idautils.FuncItems(ins))[::-1]
	for prev_ins in reverse_ins_list: 
		if prev_ins > ins:
			continue
		elif prev_ins == ins:
			last_ins = prev_ins
			continue
		# 异常处理指令地址与主函数题地址相差很远，根据这个排除异常处理，默认设置0x10
		if last_ins - prev_ins > 0x10:
			break
		last_ins = prev_ins

		op = idc.GetMnem(prev_ins)
		# mov | movsxd
		if (idc.GetOpnd(prev_ins,0) == reg1) & (op[:3] == "mov"):
			mem = idc.GetOpnd(prev_ins,1).strip("dword ptr ")
			reg_list = mem.strip("[").strip("]").split("+")
			if reg_list[1] == "4":
				reg = reg_list[0]
				mov_prev_ins = prev_ins
				while func_start <= mov_prev_ins:
					mov_op = idc.GetMnem(mov_prev_ins)
					if (idc.GetOpnd(mov_prev_ins,0) == reg) & (mov_op[:3] == "mov"):
						mov_mem = idc.GetOpnd(mov_prev_ins,1)
						mov_reg_list = mov_mem.strip("[").strip("]").split("+")
						# TODO:  0x75A294795: mov     rax, [rbx]  ->  lea     rbx, [rcx+10h],不懂这是什么情况
						if len(mov_reg_list) == 1:
							return  None

						vbtable_offset = hex(int(mov_reg_list[1].strip("h"),16))
						#print ctor_list[ctor]["vbase"]
						# TODO: 需要CFG执行流程，否则vftable会先于vbtable
						if len( ctor_list[ctor]["vbase"]) == 0:
							return None
						# TODO: vbtable偏移不对  75A7907BD  0x10|0x8
						if vbtable_offset not in ctor_list[ctor]["vbase"]:
							return None
						# 虚基类偏移vbtable_offset+vbtable_offset[0]+digit-8                                            # 32 is -4
						offset = int(vbtable_offset,16) + int(ctor_list[ctor]["vbase"][vbtable_offset][0],16) + int(digit,16) - 8
						return offset
					mov_prev_ins = idc.PrevHead(mov_prev_ins)
				
		elif (idc.GetOpnd(prev_ins,0) == reg2) & (op[:3] == "mov"):
			mem = idc.GetOpnd(prev_ins,1).strip("dword ptr ")
			reg_list = mem.strip("[").strip("]").split("+")
			if reg_list[1] == "4":
				reg = reg_list[0]
				mov_prev_ins = prev_ins
				while func_start <= mov_prev_ins:
					mov_op = idc.GetMnem(mov_prev_ins)
					if (idc.GetOpnd(mov_prev_ins,0) == reg) & (mov_op[:3] == "mov"):
						mov_mem = idc.GetOpnd(mov_prev_ins,1)
						mov_reg_list = mov_mem.strip("[").strip("]").split("+")
						vbtable_offset = hex(int(mov_reg_list[1].strip("h"),16))
																													   # 32 is -4
						offset = int(vbtable_offset,16) + int(ctor_list[ctor]["vbase"][vbtable_offset][0],16) + int(digit,16) - 8
						return offset
					mov_prev_ins = idc.PrevHead(mov_prev_ins)

		
	

def find_offset(ctor,ins,op,reg):
	op = idc.GetMnem(ins)
	if op == "lea":
		if idc.GetOpType(ins,0) == idc.o_reg:
			reg = idc.GetOpnd(ins,0)
			last_ins = idc.GetFunctionAttr(ins, idc.FUNCATTR_START)
			for next_ins in list(idautils.FuncItems(ins)):
				# 异常处理与函数主体一般相差很远，通过这个来排除异常处理代码
				if next_ins < ins:
					continue
				elif next_ins == ins:
					last_ins = next_ins
					continue
				if next_ins - last_ins > 0x10:
					break
				last_ins = next_ins

				if (idc.GetOpnd(next_ins,1) == reg) & (idc.GetMnem(next_ins) == "mov"):
					if idc.GetOpType(next_ins,0) == idc.o_phrase:
						reg = idc.GetOpnd(next_ins,0)
						reg_list = reg.strip("[").strip("]").split("+")
						if len(reg_list) == 1:
							return 0 
					elif idc.GetOpType(next_ins,0) == idc.o_displ:
						reg = idc.GetOpnd(next_ins,0)
						reg_list = reg.strip("[").strip("]").split("+")
						if len(reg_list) == 2:
							if reg_list[1].find("var") != -1:
								return -1
							elif reg_list[1].find("arg") != -1:
								return -2
							elif not reg_list[1].strip("h").isdigit():
								return -3
							return int(reg_list[1].strip("h"),16)
						elif len(reg_list) == 3:
							# 处理栈内变量和参数形式，[rsp+0C8h+var_78] [rsp+0C8h+arg_78]
							if (reg_list[2].find("var") != -1) | (reg_list[2].find("arg") != -1):
								offset = reg
								return offset
							else:
								reg1 = reg_list[0]
								reg2 = reg_list[1]
								digit = reg_list[2].strip("h")
								# 往前溯源找到vbtable
								offset = find_vbase_offset(ctor,ins,reg1,reg2,digit)
								return offset               
				
	elif op == "mov":
		# 3 is idc.o_phrase(register addressing), mov [rcx], vftable
		# 4 is idc.o_displ(Offset addressing), mov [rcx+offset], vftable
		if idc.GetOpType(ins,0) == idc.o_phrase:
			reg = idc.GetOpnd(ins,0)
			reg_list = reg.strip("[").strip("]").split("+")
			if len(reg_list) == 1:
				return 0 
		elif idc.GetOpType(ins,0) == idc.o_displ:
			reg = idc.GetOpnd(ins,0)
			reg_list = reg.strip("[").strip("]").split("+")
			if len(reg_list) == 2:
				if reg_list[1].find("var") != -1:
					return -1
				elif reg_list[1].find("arg") != -1:
					return -2
				elif not reg_list[1].strip("h").isdigit():
					return -3
				return int(reg_list[1].strip("h"),16)
			elif len(reg_list) == 3:
				# 处理栈内变量和参数形式，[rsp+0C8h+var_78] [rsp+0C8h+arg_78]
				if (reg_list[2].find("var") != -1) | (reg_list[2].find("arg") != -1):
					offset = reg
					return offset
				else:
					reg1 = reg_list[0]
					reg2 = reg_list[1]
					digit = reg_list[2].strip("h")
					# 往前溯源找到vbtable
					offset = find_vbase_offset(ctor,ins,reg1,reg2,digit)
					return offset                



def ctor_overwrite_analysis(ctor,func,hierarchy):
	if hierarchy > 4:
		return
	hierarchy += 1
	last_ins = idc.GetFunctionAttr(func, idc.FUNCATTR_START)
	flag_var = False
	flag_arg = False
	for ins in list(idautils.FuncItems(func)):
		# 异常处理与函数主体一般相差很远，通过这个来排除异常处理代码
		if ins - last_ins > 0x10:
			break
		last_ins = ins

		# 若检测到new操作则不往后进行探测，否则会把异常处理的vftable加入进去
		new = idc.GetOpnd(ins,0).strip("ds:")
		if new in new_operations:
			return

		vtable = idc.GetOperandValue(ins,1)
		op = idc.GetMnem(ins)
		if vtable in vftables_addr:

			# TODO:如何消除vftable_list中不是vftable的，目前解决方法是查看是否有cs:前缀或者特定符号如cs:__guard_dispatch_icall_fptr
			if idc.GetOpnd(ins,1).find("cs:") != -1:
				continue
			# TODO:异常处理类
			if idc.GetOpnd(ins,1) == "??_7CHResultExceptionImpl@CommonUtil@@6B@":
				continue

			print ctor,hex(ins) 

			reg = idc.GetOpnd(ins,0)
			offset = find_offset(ctor,ins,op,reg)

			# TODO：0x75A1C3914 : mov [r14+rbx*8] 
			if (offset == None) & (idc.GetOpnd(ins,1) == "??_7DnsInfoRegExState@@6B@"):
				continue
			# TODO: 0x75A88B211 : mov [r11-28h], rax
			if (offset == None) & (idc.GetOpnd(ins,1) == "??_7UfsError@@6B@"):
				continue
			# TODO: 0x75A6AC84E : mov [r11-28h], rax
			if (offset == None) & (idc.GetOpnd(ins,1) == "??_7exception@std@@6B@"):
				continue
			# TODO: 0x75A188B74 : call SymCryptHashAppendInternal
			if (offset == None) & (idc.GetOpnd(ins,1) == "SymCryptSha1Algorithm_default"):
				continue
			# TODO: 0x75A14E484 : mov     [r11-58h], rax
			if (offset == None) & (idc.GetOpnd(ins,1) == "off_75A9C6B38"):
				continue
			# TODO: 0x75A6AC82F : mov     [r11-28h], rax
			if (offset == None) & (idc.GetOpnd(ins,1) == "??_7bad_function_call@std@@6B@"):
				continue
			# TODO: 0x75A1F191E : mov     [rbp+var_38], rax
			if offset == -1:
				continue
			# TODO: 0x75A484D3F : mov     [rbp+arg_18], r15
			if offset == -2:
				continue
			# TODO: 0x75A335475 : mov     [rbp+Str], r15
			if offset == -3:
				continue
			if offset == None:
				continue

			# SOLVED: 如何处理栈内变量构造函数内联情况，目前解决方法是记录第一次的偏移为基础偏移0，后面的偏移-基础偏移即为真实偏移
			if isinstance(offset,str):
				opnd_list = offset.strip("[").strip("]").split("+")
				# 处理栈内变量形式，[rsp+0C8h+var_78]
				if opnd_list[2].find("var") != -1:
					if not flag_var:
						base_var = int(opnd_list[1].strip("h"),16) - int(opnd_list[2].strip("var_").strip(".")[0],16)
						flag_var = True
						offset = 0
					else:
						offset = int(opnd_list[1].strip("h"),16) - int(opnd_list[2].strip("var_").strip(".")[0],16) - base_var
				# 处理栈内参数形式，[rsp+0C8h+arg_78]
				elif opnd_list[2].find("arg") != -1:
					if not flag_arg:
						base_arg = int(opnd_list[1].strip("h"),16) + int(opnd_list[2].strip("arg_").strip(".")[0],16)
						flag_arg = True
						offset = 0
					else:
						offset = int(opnd_list[1].strip("h"),16) + int(opnd_list[2].strip("arg_").strip(".")[0],16) - base_arg

			print offset

			offset_str = hex(offset).strip("L")
			if offset_str in ctor_list[ctor]["this_offset"]:
				vftable_str = hex(vtable).strip("L")
				ctor_list[ctor]["this_offset"][offset_str].append(vftable_str)
			else:
				vftable_str = hex(vtable).strip("L")
				ctor_list[ctor]["this_offset"][offset_str] = list()
				ctor_list[ctor]["this_offset"][offset_str].append(vftable_str)
			
		vtable_str = hex(vtable).strip("L")
		if vtable_str in vbtable_list:
			reg = idc.GetOpnd(ins,0)
			offset = find_offset(ctor,ins,op,reg)
			print ctor,hex(ins) 
			# TODO: 
			if isinstance(offset,str):
				continue
			offset_str = hex(offset).strip("L")
			vbtable_str = hex(vtable).strip("L")
			ctor_list[ctor]["vbase"][offset_str] = list()
			# 0 is vbase offset
			# 1 is vbtable addr
			ctor_list[ctor]["vbase"][offset_str].append(vbtable_list[vtable_str])
			ctor_list[ctor]["vbase"][offset_str].append(vtable_str)
		if op == "call":
			next_func = idc.GetOperandValue(ins,0)
			if text_start <= next_func < text_end:
				ctor_overwrite_analysis(ctor,next_func,hierarchy)


# TODO:没有考虑多个类完全内联在一个函数的情况，可以通过识别this指针的位置来进行分割，this指针通过识别new操作确定
def overwrite_analysis():
	for ctor in ctor_list:
		ctor_addr = int(ctor,16)
		ctor_overwrite_analysis(ctor,ctor_addr,0)
		


# TODO: 递归深度为1  1-2
def find_next_new(func,prev_addr,hierarchy):
	find = False
	new_addr = None
	'''
	if hierarchy > 0:
		return find
	'''
	#hierarchy += 1
	last_ins = idc.GetFunctionAttr(func, idc.FUNCATTR_START)
	for ins in list(idautils.FuncItems(func)):
		# 异常处理与函数主体一般相差很远，通过这个来排除异常处理代码
		if ins - last_ins > 0x10:
			break
		last_ins = ins

		new = idc.GetOpnd(ins,0).strip("ds:")
		op = idc.GetMnem(ins)
		if new in new_operations:
			find = True
			addr = hex(ins).strip("L")
			func_addr = hex(idc.GetFunctionAttr(ins, idc.FUNCATTR_START)).strip("L")
			# new operation 与构造在同一个函数中的两个不同子函数中 hierarchy=1
			# 构造函数在new operation的上层 hierarchy = 0,并且addr改为记录上层调用该函数的地址
			if hierarchy == 0:
				new_addr = {"addr":prev_addr,"func_addr":func_addr,"hierarchy":hierarchy,"prev_addr":1}
			else:
				new_addr = {"addr":addr,"func_addr":func_addr,"hierarchy":hierarchy}
			return find,new_addr
		'''
		elif op == "call":
			next_func = idc.GetOperandValue(ins,0)
			find = find_next_new(next_func,hierarchy)
			if find:
				return find
		'''
	return find,new_addr

# 取上两层  有的函数有wrap，需要再跳一层
def find_xref_new(ins,hierarchy):
	find = False
	new_addr = None
	if hierarchy > 1:
		return find,new_addr
	hierarchy += 1

	#print hex(ins)
	last_ins = idc.GetFunctionAttr(ins, idc.FUNCATTR_START)
	reverse_ins_list = list(idautils.FuncItems(ins))[::-1]
	for prev_ins in reverse_ins_list: 
		if prev_ins > ins:
			continue
		elif prev_ins == ins:
			last_ins = prev_ins
			continue
		# 异常处理指令地址与主函数题地址相差很远，根据这个排除异常处理，默认设置0x10
		if last_ins - prev_ins > 0x10:
			break
		last_ins = prev_ins
		new = idc.GetOpnd(prev_ins,0).strip("ds:")
		op = idc.GetMnem(prev_ins)
		if new in new_operations:
			find = True
			addr = hex(prev_ins).strip("L")
			func_addr = hex(idc.GetFunctionAttr(prev_ins, idc.FUNCATTR_START)).strip("L")
			# new operation 在构造函数的上一层
			new_addr = {"addr":addr,"func_addr":func_addr,"hierarchy":-1}
			return find,new_addr
		#处理情景： A->new operation
		#            ctor()
		#         所以需要对A函数中的call进行一层搜索
		elif op == "call":
			next_func = idc.GetOperandValue(prev_ins,0)
			addr = hex(prev_ins).strip("L")
			find,new_addr = find_next_new(next_func,addr,1)
			if find:
				return find,new_addr

	func_start = idc.GetFunctionAttr(ins, idc.FUNCATTR_START)
	xrefs = list(idautils.XrefsTo(func_start))
	for xref in xrefs:
		# 一般构造函数都是通过call调用，异常处理则是常通过jmp等跳转语句
		# SOLVED:虚基类的异常处理的析构函数无法去除它使用的也是call  解决方法：异常处理指令地址与主函数题地址相差很远，根据这个排除，默认设置0x10
		if (text_start <= xref.frm < text_end) & (idc.GetMnem(xref.frm) == "call"):
			func_start = idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_START)
			find,new_addr = find_xref_new(xref.frm,hierarchy)
			if find:
				return find,new_addr
		
	return find,new_addr

'''
寻找new操作

参数：
	ins：起始指令地址
	pdb：IDA是否加载PDB文件

返回：
	find: 若找到new操作返回True，否则返回False
'''
'''
Looking for new operation

Args:
	ins: start instruction address
	pdb: whether IDA loads PDB files

Return:
	find: returns True if the new operation is found, otherwise returns False
'''
def check_new(ins,pdb):
	find = False
	new_addr = None
	last_ins = idc.GetFunctionAttr(ins, idc.FUNCATTR_START)
	reverse_ins_list = list(idautils.FuncItems(ins))[::-1]

	for prev_ins in reverse_ins_list: 
		if prev_ins > ins:
			continue
		elif prev_ins == ins:
			last_ins = prev_ins
			continue
		if last_ins - prev_ins > 0x10:
			break
		last_ins = prev_ins

		new = idc.GetOpnd(prev_ins,0).strip("ds:")
		op = idc.GetMnem(prev_ins)
		if new in new_operations:
			find = True
			addr = hex(prev_ins).strip("L")
			func_addr = hex(idc.GetFunctionAttr(prev_ins, idc.FUNCATTR_START)).strip("L")
			# new operation 与 构造函数在同一个函数中
			new_addr = {"addr":addr,"func_addr":func_addr,"hierarchy":0}

			return find,new_addr
		# TODO:没有符号表的时候启动，可能不准，会有误报
		if pdb == 0:
			if op == "call":
				next_func = idc.GetOperandValue(prev_ins,0)
				addr = hex(prev_ins).strip("L")
				find = find_next_new(next_func,addr,0)
				if find:
					return find
	# ELFTODO：只需要找到完全内联的情况就可以
	if pdb == 0:
		func_start = idc.GetFunctionAttr(ins, idc.FUNCATTR_START)
		xrefs = list(idautils.XrefsTo(func_start))
		for xref in xrefs:
			# 一般构造函数都是通过call调用，异常处理则是常通过jmp等跳转语句
			# SOLVED:虚基类的异常处理的析构函数无法去除它使用的也是call  解决方法：异常处理指令地址与主函数题地址相差很远，根据这个排除，默认设置0x10
			# jmp的时候要检查函数指令数是否为1，是否是构造函数的wrap，异常处理也有jmp
			if (text_start <= xref.frm < text_end) and ((idc.GetMnem(xref.frm) == "call") or ((idc.GetMnem(xref.frm) == "jmp") and (len(list(idautils.FuncItems(xref.frm)))== 1))):
				if func_start not in delete_xref_list:
					func_start = idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_START)
					find,new_addr = find_xref_new(xref.frm,0)
					if find:
						return find,new_addr
	return find,new_addr


def find_ctor(xref_addr,pdb):
	find = False
	new_addr = None
	if idc.GetOperandValue(xref_addr,1) in vftables_addr:
		find,new_addr = check_new(xref_addr,pdb)
	return find,new_addr


'''
MSVC: 启发式搜索构造函数

对每个vftable进行交叉引用查询，排除掉delete_xref_list的函数（与析构函数相关的函数），
然后遍历函数后向查找new操作，查找层级为当前层和上一层

参数：
	pdb： IDA是否加载PDB文件，1为加载，0为未加载，默认为未加载
'''

'''
MSVC: Heuristic search constructor

Perform cross-reference query on each vftable, excluding functions of delete_xref_list (functions related to destructor),
Then traverse the function to find the new operation backward, the search level is the current layer and the previous layer

Args:
	pdb: Whether IDA loads PDB file, 1 is loaded, 0 is not loaded, default is not loaded
'''
def fast_check_ctor_msvc(pdb=0):
	for vftable in vftable_list:
		vftable_addr = int(vftable,16)
		xrefs = list(idautils.XrefsTo(vftable_addr))
		for xref in xrefs:
			func = idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_START)
			if text_start <= func < text_end:
				find = False
				if func not in delete_xref_list:
					find , new_addr= check_new(xref.frm,pdb)
					if find:                    
						func_str = hex(func).strip("L")
						if func_str not in ctor_list:
							ctor_list[func_str] = dict()
							ctor_list[func_str]["this_offset"] = dict()
							#ctor_list[func_str]["vbase"] = dict()
							ctor_list[func_str]["new_addr"] = dict()
							ctor_list[func_str]["new_addr"] = new_addr
					else:
						func_str = hex(func).strip("L")
						if func_str not in ctor_list:
							ctor_list[func_str] = dict()
							ctor_list[func_str]["this_offset"] = dict()
							ctor_list[func_str]["new_addr"] = dict()
							ctor_list[func_str]["new_addr"] = {"hierarchy":1}


'''
GCC: 启发式搜索构造函数

对每个vftable进行交叉引用查询，排除掉delete_xref_list的函数（与析构函数相关的函数），
然后遍历函数后向查找new操作，查找层级为当前层和上一层

参数：
	pdb： IDA是否加载PDB文件，1为加载，0为未加载，默认为未加载
'''

'''
GCC: Heuristic search constructor

Perform cross-reference query on each vftable, excluding functions of delete_xref_list (functions related to destructor),
Then traverse the function to find the new operation backward, the search level is the current layer and the previous layer

Args:
	pdb: Whether IDA loads PDB file, 1 is loaded, 0 is not loaded, default is not loaded
'''
def fast_check_ctor_gcc(pdb=0):
	for vftable in vftable_list:
		vftable_addr = int(vftable,16)
		xrefs = list(idautils.XrefsTo(vftable_addr))
		if len(xrefs) != 0:
			for xref in xrefs:
				func = idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_START)
				if text_start <= func < text_end:
					find = False
					if func not in delete_xref_list:
						find , new_addr= check_new(xref.frm,pdb)
						if find:                    
							func_str = hex(func).strip("L")
							if func_str not in ctor_list:
								ctor_list[func_str] = dict()
								ctor_list[func_str]["this_offset"] = dict()
								#ctor_list[func_str]["vbase"] = dict()
								ctor_list[func_str]["new_addr"] = dict()
								ctor_list[func_str]["new_addr"] = new_addr
						# ELFTODO: 上面找到的都是可能存在函数内联的
						else:
							func_str = hex(func).strip("L")
							if func_str not in ctor_list:
								ctor_list[func_str] = dict()
								ctor_list[func_str]["this_offset"] = dict()
								ctor_list[func_str]["new_addr"] = dict()
								ctor_list[func_str]["new_addr"] = {"hierarchy":1}
		else:
			
			got_xrefs = list(idautils.XrefsTo(vftable_addr - 0x10))
			if len(got_xrefs)!= 0:
				for got_xref in got_xrefs:
					# 获取got的vftable的交叉引用
					if got_start <= got_xref.frm < got_end:
						got_xrefs2 = list(idautils.XrefsTo(got_xref.frm))
						if len(got_xrefs2) != 0:
							for got in got_xrefs2:
								find = False
								func = idc.GetFunctionAttr(got.frm, idc.FUNCATTR_START)
								if text_start <= func < text_end:
									if func not in delete_xref_list:
										find , new_addr= check_new(got.frm,pdb)
										if find:                    
											func_str = hex(func).strip("L")
											if func_str not in ctor_list:
												ctor_list[func_str] = dict()
												ctor_list[func_str]["this_offset"] = dict()
												#ctor_list[func_str]["vbase"] = dict()
												ctor_list[func_str]["new_addr"] = dict()
												ctor_list[func_str]["new_addr"] = new_addr
										# ELFTODO: 上面找到的都是可能存在函数内联的
										else:
											func_str = hex(func).strip("L")
											if func_str not in ctor_list:
												ctor_list[func_str] = dict()
												ctor_list[func_str]["this_offset"] = dict()
												ctor_list[func_str]["new_addr"] = dict()
												ctor_list[func_str]["new_addr"] = {"hierarchy":1}
					# 处理GCC下有的vftable从OffsetToTop处获取
					elif text_start <= got_xref.frm < text_end:
						find = False
						func = idc.GetFunctionAttr(got_xref.frm, idc.FUNCATTR_START)
						if text_start <= func < text_end:
							if func not in delete_xref_list:
								find , new_addr= check_new(got_xref.frm,pdb)
								if find:                    
									func_str = hex(func).strip("L")
									if func_str not in ctor_list:
										ctor_list[func_str] = dict()
										ctor_list[func_str]["this_offset"] = dict()
										#ctor_list[func_str]["vbase"] = dict()
										ctor_list[func_str]["new_addr"] = dict()
										ctor_list[func_str]["new_addr"] = new_addr
								# ELFTODO: 上面找到的都是可能存在函数内联的
								else:
									func_str = hex(func).strip("L")
									if func_str not in ctor_list:
										ctor_list[func_str] = dict()
										ctor_list[func_str]["this_offset"] = dict()
										ctor_list[func_str]["new_addr"] = dict()
										ctor_list[func_str]["new_addr"] = {"hierarchy":1}


			else:
				# 有的从OffsetToVbase获取got
				got_xrefs = list(idautils.XrefsTo(vftable_addr - 0x18))
				if len(got_xrefs)!= 0:
					for got_xref in got_xrefs:
						if got_start <= got_xref.frm < got_end:
							got_xrefs2 = list(idautils.XrefsTo(got_xref.frm))
							if len(got_xrefs2) != 0:
								for got in got_xrefs2:
									find = False
									func = idc.GetFunctionAttr(got.frm, idc.FUNCATTR_START)
									if func not in delete_xref_list:
										find , new_addr= check_new(got.frm,pdb)
										if find:                    
											func_str = hex(func).strip("L")
											if func_str not in ctor_list:
												ctor_list[func_str] = dict()
												ctor_list[func_str]["this_offset"] = dict()
												#ctor_list[func_str]["vbase"] = dict()
												ctor_list[func_str]["new_addr"] = dict()
												ctor_list[func_str]["new_addr"] = new_addr
										# ELFTODO: 上面找到的都是可能存在函数内联的
										else:
											func_str = hex(func).strip("L")
											if func_str not in ctor_list:
												ctor_list[func_str] = dict()
												ctor_list[func_str]["this_offset"] = dict()
												ctor_list[func_str]["new_addr"] = dict()
												ctor_list[func_str]["new_addr"] = {"hierarchy":1}


'''
将dtor函数递归扫描覆写操作，有覆写操作就添加到delete_xref_list中，以方便后面使用交叉引用排除dtor及相关函数来确定ctor

参数：
	func: 函数地址
	hierarchy： 递归次数
'''

'''
The dtor function recursively scans and overwrites the operation. If there is an overwrite operation, it is added to delete_xref_list to facilitate the use of cross-references to exclude dtor and related functions to determine the ctor.

Args:
	func: function address
	hierarchy: recursion times
'''
def add_delete_addr(func,hierarchy):
	# TODO:hierarchy 影响性能需要调整，1-4
	if hierarchy > 1:
		return
	hierarchy += 1

	for ins in list(idautils.FuncItems(func)):
		op = idc.GetMnem(ins)
		if idc.GetOperandValue(ins,1) in vftables_addr:
			if func in delete_xref_list:
				continue
			delete_xref_list.append(func)

		# 处理从got表获取vftable的操作
		elif (op == "mov") and (hasgot == 1):
			got_addr = idc.GetOperandValue(ins,1)
			if got_start <= got_addr < got_end:
				got_data = idc.Qword(got_addr)

				isvftable = got_data + 0x10			
				if isvftable in vftables_addr:
					if func in delete_xref_list:
						continue
					delete_xref_list.append(func)
				else:
					isvftable = got_data + 0x18			
					if isvftable in vftables_addr:
						if func in delete_xref_list:
							continue
						delete_xref_list.append(func)
				# 下面的效率较低
				'''
				reg = idc.GetOpnd(ins,0)
				func_end =  idc.GetFunctionAttr(func, idc.FUNCATTR_END)
				next_ins = idc.NextHead(ins)
				while next_ins < func_end:
					next_op = idc.GetMnem(next_ins)
					if next_op == "lea":
						next_opnd = idc.GetOpnd(next_ins,1)
						reg_list = next_opnd.strip("[").strip("]").split("+")
						if reg_list[0] == reg:
							offset = int(reg_list[1].strip("h"),16)
							isvftable = got_data + offset
							if isvftable in vftables_addr:
								if func in delete_xref_list:
									continue
								delete_xref_list.append(func)
					elif next_op == "add":
						next_reg = idc.GetOpnd(next_ins,0)
						if next_reg == reg:
							
							offset = int(idc.GetOpnd(next_ins,1).strip("h"),16)
							isvftable = got_data + offset
							
							if isvftable in vftables_addr:
								if func in delete_xref_list:
									continue
								delete_xref_list.append(func)
					next_ins = idc.NextHead(next_ins)
				'''

		elif  op == "call":
			next_func = idc.GetOperandValue(ins,0)
			add_delete_addr(next_func,hierarchy)
		# 处理GCC的通过plt表的跳转
		elif (op == "jmp") and (idc.GetOpnd(ins,0)[:3] == "cs:") and (hasplt == 1) and (plt_start <= ins < plt_end):
			got_plt_addr = idc.GetOperandValue(ins,0)
			next_func = idc.Qword(got_plt_addr)
			# jmp 指令不占次数
			hierarchy -= 1
			add_delete_addr(next_func,hierarchy)


def delete_xref_msvc():  
	for vftable in vftable_list:
		if vftable_list[vftable]["dtor"] != 0:
			dtor_addr = int(vftable_list[vftable]["dtor"],16)
			add_delete_addr(dtor_addr,0)
 

def delete_xref_gcc():
	for vftable in vftable_list:
		if vftable_list[vftable]["dtor"] != 0:
			dtor_addr = int(vftable_list[vftable]["dtor"],16)
			if dtor_addr not in delete_xref_list:
				add_delete_addr(dtor_addr,0)
		
		

'''
MSVC：寻找delete操作

参数：
	func: 函数地址
	hierarchy：递归次数	

返回：
	find：若找到delete操作返回True，否则返回False
'''
'''
MSVC: looking for delete operation
	
Args:
	func: function address
	hierarchy: recursion times

Return:
	find: returns True if the delete operation is found, otherwise returns False
'''
def check_delete_msvc(func,hierarchy):
	find = False
	if hierarchy > 1:
		return find
	hierarchy += 1

	# 不需要考虑异常处理，异常处理的析构函数没有delete操作，而且有些delete基本快与函数主体处理相差很远
	for ins in list(idautils.FuncItems(func)):

		delete = idc.GetOpnd(ins,0).strip("ds:")
		op = idc.GetMnem(ins)
		if delete in delete_operations:
			find = True
			return find
		elif op == "call":
			next_func = idc.GetOperandValue(ins,0)
			find = check_delete_msvc(next_func,hierarchy)
			if find:
				return find
	return find

'''
GCC：寻找delete操作

参数：
	func: 函数地址
	hierarchy：递归次数	

返回：
	find：若找到delete操作返回True，否则返回False
'''
'''
GCC: looking for delete operation
	
Args:
	func: function address
	hierarchy: recursion times

Return:
	find: returns True if the delete operation is found, otherwise returns False
'''
def check_delete_gcc(func,hierarchy):
	find = False
	if hierarchy > 1:
		return find
	hierarchy += 1

	# 不需要考虑异常处理，异常处理的析构函数没有delete操作，而且有些delete基本快与函数主体处理相差很远
	for ins in list(idautils.FuncItems(func)):
		delete = idc.GetOpnd(ins,0).strip("ds:")
		op = idc.GetMnem(ins)
		if delete in delete_operations:
			next_ins = idc.NextHead(ins)
			next2_ins = idc.NextHead(next_ins)
			unwind = idc.GetOpnd(next2_ins,0)
			if unwind != "__Unwind_Resume":
				find = True
				return find
		elif op == "call":
			next_func = idc.GetOperandValue(ins,0)
			find = check_delete_gcc(next_func,hierarchy)
			if find:
				return find
	return find

'''
MSVC: 寻找vftable覆写操作

参数：
	func: 函数地址
	hierarchy：递归次数

返回：
	find: 找到vftable覆写操作为True，否则为False
'''
'''
MSVC: looking for vftable overwrite operations

Args:
	func: function address
	hierarchy: Recursion times

Return:
	find: find the vftable override operation is True, otherwise it is False

aka mov [reg+offset], vftable
'''
# TODO: 有的析构函数没有delete操作
#       有的析构函数没有vftable覆写操作
def find_dtor_msvc(func,hierarchy):
	find = False
	if hierarchy > 1:
		return find
	hierarchy += 1

	last_ins = idc.GetFunctionAttr(func, idc.FUNCATTR_START)
	for ins in list(idautils.FuncItems(func)):
		# 异常处理与函数主体一般相差很远，通过这个来排除异常处理代码
		if ins - last_ins > 0x10:
			break
		last_ins = ins

		op = idc.GetMnem(ins)
		# find 2th OperandValue is vftable
		if idc.GetOperandValue(ins,1) in vftables_addr:         
			if op == "lea":
				if idc.GetOpType(ins,0) == idc.o_reg:
					reg = idc.GetOpnd(ins,0)
					func_end =  idc.GetFunctionAttr(func, idc.FUNCATTR_END)
					next_ins = idc.NextHead(ins)
					while next_ins < func_end:
						if (idc.GetOpnd(next_ins,1) == reg) & (idc.GetMnem(next_ins) == "mov"):
							if (idc.GetOpType(next_ins,0) == idc.o_phrase) | (idc.GetOpType(next_ins,0) == idc.o_displ):
								find = True
								# 若找到vftable则添加进列表中，一般构造函数不为虚函数
								# TODO：若构造函数为虚函数可能造成漏报
								delete_xref_list.append(func)
								return find
						next_ins = idc.NextHead(next_ins)
			elif op == "mov":
				# 3 is idc.o_phrase(register addressing), mov [rcx], vftable
				# 4 is idc.o_displ(Offset addressing), mov [rcx+offset], vftable
				if (idc.GetOpType(ins,0) == idc.o_phrase) | (idc.GetOpType(ins,0) == idc.o_displ):
					find = True
					# 若找到vftable则添加进列表中，一般构造函数不为虚函数
					# TODO：若构造函数为虚函数可能造成漏报
					delete_xref_list.append(func)
					return find
		if op == "call":
			next_func = idc.GetOperandValue(ins,0)
			# recursive query, but the hierarchy <= 1
			find = find_dtor_msvc(next_func,hierarchy)
			if find:
				return find
	return find
'''
GCC: 寻找vftable覆写操作

参数：
	func: 函数地址
	hierarchy：递归次数

返回：
	find: 找到vftable覆写操作为True，否则为False
'''
'''
GCC: looking for vftable overwrite operations

Args:
	func: function address
	hierarchy: Recursion times

Return:
	find: find the vftable override operation is True, otherwise it is False

aka mov [reg+offset], vftable
'''
def find_dtor_gcc(func,hierarchy):
	find = False
	if hierarchy > 1:
		return find
	hierarchy += 1

	last_ins = idc.GetFunctionAttr(func, idc.FUNCATTR_START)
	for ins in list(idautils.FuncItems(func)):
		# 异常处理与函数主体一般相差很远，通过这个来排除异常处理代码
		if ins - last_ins > 0x10:
			break
		last_ins = ins

		op = idc.GetMnem(ins)
		# find 2th OperandValue is vftable
		if idc.GetOperandValue(ins,1) in vftables_addr:         
			if op == "lea":
				if idc.GetOpType(ins,0) == idc.o_reg:
					reg = idc.GetOpnd(ins,0)
					func_end =  idc.GetFunctionAttr(func, idc.FUNCATTR_END)
					next_ins = idc.NextHead(ins)
					while next_ins < func_end:
						if (idc.GetOpnd(next_ins,1) == reg) & (idc.GetMnem(next_ins) == "mov"):
							if (idc.GetOpType(next_ins,0) == idc.o_phrase) | (idc.GetOpType(next_ins,0) == idc.o_displ):
								find = True
								# 若找到vftable则添加进列表中，一般构造函数不为虚函数
								# TODO：若构造函数为虚函数可能造成漏报
								delete_xref_list.append(func)
								return find
						next_ins = idc.NextHead(next_ins)
			elif op == "mov":
				# 3 is idc.o_phrase(register addressing), mov [rcx], vftable
				# 4 is idc.o_displ(Offset addressing), mov [rcx+offset], vftable
				if (idc.GetOpType(ins,0) == idc.o_phrase) | (idc.GetOpType(ins,0) == idc.o_displ):
					find = True
					# 若找到vftable则添加进列表中，一般构造函数不为虚函数
					# TODO：若构造函数为虚函数可能造成漏报
					delete_xref_list.append(func)
					return find
		
		# 处理从got表获取vftable的操作
		if op == "mov":
			got_addr = idc.GetOperandValue(ins,1)
			if got_start <= got_addr < got_end:
				got_data = idc.Qword(got_addr)
				reg = idc.GetOpnd(ins,0)
				func_end =  idc.GetFunctionAttr(func, idc.FUNCATTR_END)
				next_ins = idc.NextHead(ins)
				while next_ins < func_end:
					next_op = idc.GetMnem(next_ins)
					if next_op == "lea":
						next_opnd = idc.GetOpnd(next_ins,1)
						reg_list = next_opnd.strip("[").strip("]").split("+")
						if (reg_list[0] == reg) and ("h" in reg_list[1]):
							offset = int(reg_list[1].strip("h"),16)
							isvftable = got_data + offset
							if isvftable in vftables_addr:
								# 若找到vftable则添加进列表中，一般构造函数不为虚函数
								# TODO：若构造函数为虚函数可能造成漏报
								delete_xref_list.append(func)
								find = True								
								return find
					elif next_op == "add":
						next_reg = idc.GetOpnd(next_ins,0)
						if next_reg == reg:
							if ("[" not in idc.GetOpnd(next_ins,1)) and ("h" in idc.GetOpnd(next_ins,1)):
								offset = int(idc.GetOpnd(next_ins,1).strip("h"),16)
								isvftable = got_data + offset
								
								if isvftable in vftables_addr:
									find = True
									# 若找到vftable则添加进列表中，一般构造函数不为虚函数
									# TODO：若构造函数为虚函数可能造成漏报
									delete_xref_list.append(func)
									return find
					next_ins = idc.NextHead(next_ins)
		# 处理GCC下有的vftable从OffsetToTop处获取
		if op == "lea":
			offsetToTop_addr = idc.GetOperandValue(ins, 1)
			if (drrdata_start <= offsetToTop_addr < drrdata_end) or (rodata_start <= offsetToTop_addr < rodata_end):
				# ELFTODO:不知道有没有从OffsetToVbase直接获取的
				vftable_addr = offsetToTop_addr + 0x10
				if vftable_addr in vftables_addr:
					find = True
					# 若找到vftable则添加进列表中，一般构造函数不为虚函数
					# TODO：若构造函数为虚函数可能造成漏报
					delete_xref_list.append(func)
					return find
			

		if op == "call":
			next_func = idc.GetOperandValue(ins,0)
			# recursive query, but the hierarchy <= 1
			find = find_dtor_gcc(next_func,hierarchy)
			if find:
				return find
		# 处理GCC的通过plt表的跳转
		elif (op == "jmp") and (idc.GetOpnd(ins,0)[:3] == "cs:") and (plt_start <= ins < plt_end):
			got_plt_addr = idc.GetOperandValue(ins,0)
			next_func = idc.Qword(got_plt_addr)
			# jmp 指令不占次数
			hierarchy -= 1
			find = find_dtor_gcc(next_func,hierarchy)
			if find:
				return find
	return find

'''
vftable分析

1.识别纯虚函数
2.关联分析
3.虚基类分析
4.交叉引用分析
'''
'''
vftable analysis

1. Identify pure virtual functions
2. Association analysis
3. Virtual base class analysis
4. Cross-reference analysis
'''
# TODO: 还有一些vftable既没有析构函数也没有构造函数，交叉引用也没有new和delete，仅在.data段有交叉引用
def del_not_vftable_msvc():
	global purecall_addr
	for vftable in vftable_list:
		if vftable_list[vftable]["dtor"] == 0:
			not_vftable = True
			# 识别纯虚函数
			for func in vftable_list[vftable]["functions"]:
				if purecall_addr == 0:
					# _purecall | _purecall_0
					if idc.GetFunctionName(int(func,16)).find("_purecall") != -1:
						purecall_addr = func
						not_vftable = False
						break
				else:
					if func == purecall_addr:
						not_vftable = False
						break
			if not not_vftable:
				vftable_list[vftable]["has_purecall"] = 1
				continue
			# 关联分析：若一个dtor==0的vftable中的函数在dtor!=0的vftable的函数表中出现过，则存在关联关系，
			for func in vftable_list[vftable]["functions"]:
				has_correlation = False
				for vftable2 in vftable_list:
					if (vftable_list[vftable2]["dtor"] != 0) & (vftable != vftable2):
						if func in vftable_list[vftable2]["functions"]:
							vftable_list[vftable]["has_correlation"] = 1
							has_correlation = True
							not_vftable = False
							break
				if has_correlation:
					break
			
			if not_vftable:
				vftable_list[vftable]["not_vftable"] = 1
	# TODO: 虚继承的非虚基类vftable识别,识别虚基类函数的模式 [rcx-4]
	for vftable in vftable_list:
		if vftable_list[vftable]["dtor"] != 0:
			opd = idc.GetOpnd(int(vftable_list[vftable]["functions"][0],16),1)
			if opd.find("[") != -1:
				xrefs = list(idautils.XrefsTo(int(vftable,16)))
				for xref in xrefs:
					if text_start <= xref.frm < text_end:
						for ins in list(idautils.FuncItems(xref.frm)):
							vf = hex(idc.GetOperandValue(ins, 1)).strip("L")
							if vf in vftable_list :
								if "not_vftable" in vftable_list[vf] :
									if vftable_list[vf]["not_vftable"] == 1:
										vftable_list[vf]["not_vftable"] = 0
										vftable_list[vf]["virtual_inherit"] = 1
										# 如果vbtable只有一个把vbtable加进去
										vbtable = list()
										for ins2 in list(idautils.FuncItems(xref.frm)):
											vb = hex(idc.GetOperandValue(ins2, 1)).strip("L")
											if vb in vbtable_list:
												vbtable.append(vb)
										if len(vbtable) == 1:
											vftable_list[vf]["vbtable"] = vbtable[0]


						break
		'''				
		# TODO: 交叉引用找到new或者delete操作
		# 可能导致构造函数被识别为析构函数，所以暂时去掉
		if "not_vftable" in vftable_list[vftable] :
			if vftable_list[vftable]["not_vftable"] == 1:
				xrefs = list(idautils.XrefsTo(int(vftable,16)))
				for xref in xrefs:
					if text_start <= xref.frm < text_end:
						# TODO:pdb可调
						ctor_flag,new_addr = find_ctor(xref.frm,pdb=1)
						find = ctor_flag | find_dtor_msvc(xref.frm,0)
						if find:
							vftable_list[vftable]["not_vftable"] = 0
							vftable_list[vftable]["xref"] = 1
							break
		'''

	# 删除not_vftable == 1的项
	# TODO:GCC会删除一些vftable
	'''
	del_list = list()
	for vftable in vftable_list:
		if "not_vftable" in vftable_list[vftable] :
			if vftable_list[vftable]["not_vftable"] == 1:
				del_list.append(vftable)
	for vftable in del_list:
		#print vftable,vftable_list[vftable]
		del vftable_list[vftable]
	'''

'''
MSVC: 搜索析构函数

若是析构函数的包装函数，则寻找其真正的析构函数
'''
'''
MSVC:　Search destructor

if the function is wrapper function of destructor, search the real destructor
'''
def check_dtor_msvc():
	for vftable in vftable_list:
		find = False
		for func in vftable_list[vftable]["functions"]:
			ea = int(func,16)
			count = len(list(idautils.FuncItems(ea)))
			func_end = idc.GetFunctionAttr(ea, idc.FUNCATTR_END)
			ins_end = idc.PrevHead(func_end)            
			# jmp function always changes it's this_ptr, so the ins is small and the last ins is jmp
			if (0 < count <=5) & (idc.GetMnem(ins_end) == "jmp"):
				jmp_func = idc.GetOperandValue(ins_end, 0)
				# TODO:放宽要求，由与操作变成或 => 有的析构函数没有覆写操作|有的析构函数没有delete操作
				find = find_dtor_msvc(jmp_func,0) | check_delete_msvc(jmp_func,0)
				if find:
					vftable_list[vftable]["jmp_dtor"] = hex(ea).strip("L")
					vftable_list[vftable]["dtor"] = hex(jmp_func).strip("L")
					break
			else:
				find = find_dtor_msvc(ea,0) | check_delete_msvc(ea,0)
				if find:
					vftable_list[vftable]["jmp_dtor"] = 0
					vftable_list[vftable]["dtor"] = hex(ea).strip("L")
					break
			'''
			if (0 < count <=5) & (idc.GetMnem(ins_end) == "jmp"):
				jmp_func = idc.GetOperandValue(ins_end, 0)
				find = find_dtor_msvc(jmp_func,0)
				if find:
					find = check_delete_msvc(jmp_func,0)
					if find:
						vftable_list[vftable]["jmp_dtor"] = hex(ea).strip("L")
						vftable_list[vftable]["dtor"] = hex(jmp_func).strip("L")
						break
			else:
				find = find_dtor_msvc(ea,0)
				if find:
					find = check_delete_msvc(ea,0)
					if find:
						vftable_list[vftable]["jmp_dtor"] = 0
						vftable_list[vftable]["dtor"] = hex(ea).strip("L")
						break
			'''
		if not find:
			vftable_list[vftable]["jmp_dtor"] = 0
			vftable_list[vftable]["dtor"] = 0
	del_not_vftable_msvc()

'''
GCC: 搜索析构函数

若是析构函数的包装函数，则寻找其真正的析构函数
'''
'''
GCC:　Search destructor

if the function is wrapper function of destructor, search the real destructor
'''
def check_dtor_gcc():
	for vftable in vftable_list:
		find = False
		for func in vftable_list[vftable]["functions"]:
			ea = int(func,16)
			count = len(list(idautils.FuncItems(ea)))
			func_end = idc.GetFunctionAttr(ea, idc.FUNCATTR_END)
			ins_end = idc.PrevHead(func_end)            
			# jmp function always changes it's this_ptr, so the ins is small and the last ins is jmp
			if (0 < count <=5) & (idc.GetMnem(ins_end) == "jmp"):
				jmp_func = idc.GetOperandValue(ins_end, 0)
				# TODO:放宽要求，由与操作变成或 => 有的析构函数没有覆写操作|有的析构函数没有delete操作
				find = find_dtor_gcc(jmp_func,0) & check_delete_gcc(jmp_func,0)
				if find:
					vftable_list[vftable]["jmp_dtor"] = hex(ea).strip("L")
					vftable_list[vftable]["dtor"] = hex(jmp_func).strip("L")
					break
			else:
				find = find_dtor_gcc(ea,0) & check_delete_gcc(ea,0)
				if find:
					vftable_list[vftable]["jmp_dtor"] = 0
					vftable_list[vftable]["dtor"] = hex(ea).strip("L")
					break
		if not find:
			vftable_list[vftable]["jmp_dtor"] = 0
			vftable_list[vftable]["dtor"] = 0
	# ELFTODO: 处理中间基类或者虚基类合并的条件可在这里增加
	#del_not_vftable_gcc()

'''
MSVC:寻找vftable, 将其加入vftable_list中

1.data在代码段
2.vftable第一项有交叉引用；若不存在交叉引用，并且当前地址与上一个记录地址相连，将其加入vftable函数列表中

参数： 
	seg： 段起始地址

'''
''' 
MSVC: Search vftable, and add it into vftable_list

1.data is in .text
2.the 1th addr of vftable has xref; If one hasn't xref and cur_addr - last_add_addr == 8, it will add in vftable following cur_vftable_start 

Args:
	seg: segment address

'''
def find_vftable_msvc(seg):
	seg_start = idc.SegStart(seg)
	seg_end = idc.SegEnd(seg)
	cur_addr = seg
	cur_vftable_start = ""
	last_add_addr = 0
	
	while cur_addr <= seg_end - 8:                   #32 is 4
		data = idc.Qword(cur_addr)                  #32 is Dword
		# 检测data是否在.text段
		# check if the data in .text
		if text_start <= data < text_end:
			xrefs = list(idautils.XrefsTo(cur_addr))
			if len(xrefs) !=0:  
				cur_vftable_start = hex(cur_addr).strip("L")
				vftable_list[cur_vftable_start] = dict()
				vftable_list[cur_vftable_start]["functions"] = [hex(data).strip("L")]

				# 如果vftable有符号，则将符号加入list中
				
				vftable_symbols = idc.GetOpnd(xrefs[0].frm,1).split("@")
				if len(vftable_symbols) > 1:
					vftable_symbol = vftable_symbols[0][4:]
					vftable_symbol = re.sub(r'^\?\$','',vftable_symbol)
					vftable_list[cur_vftable_start]["symbol"] = vftable_symbol
				'''
				# 完整符号
				vftable_symbol = idc.GetOpnd(xrefs[0].frm,1)
				vftable_symbols = vftable_symbol.split("@")
				if len(vftable_symbols) > 1:
					vftable_symbol = vftable_symbol[4:]
					vftable_symbol = re.sub(r'^\?\$','',vftable_symbol)
					vftable_list[cur_vftable_start]["symbol"] = vftable_symbol
				'''

				last_add_addr = cur_addr
				if use_RTTI:
					vftable_list[cur_vftable_start]["rtti"] = get_vftable_rtti(cur_addr)
				else:
					vftable_list[cur_vftable_start]["rtti"] = 0
				#print cur_vftable_start,vftable_list[cur_vftable_start]
			elif cur_addr - last_add_addr == 8:      #32 is 4
				vftable_list[cur_vftable_start]["functions"].append(hex(data).strip("L"))
				last_add_addr = cur_addr
		cur_addr += 8                                #32 is 4

def search_vftable_list_msvc():
	for seg in idautils.Segments():
		if idc.SegName(seg) in vftable_section_names:
			find_vftable_msvc(seg)
'''
MSVC:寻找vbtable, 将其加入vbtable_list中

vbtable有两个字段，且字段大小为定值4字节：
			--------
			|vftptr|<--
			--------   |  -4 or -8
			|vbtptr|---
			--------
			| ...  | 	
1.第一个字段记录着与之对应的vftable_ptr偏移，因为是紧挨着所以一般为定值，32位为0xFFFFFFFC(-4)，64位下为0xFFFFFFF8(-8)
2.第二个字段记录当前this指针与虚基类的偏移

参数： 
	seg： 段起始地址
'''
'''
MSVC: Search vbtable, and add it into vbtable_list

1.the 1th field is vftable_ptr offset, x32 is 0xFFFFFFFC(-4), x64 is 0xFFFFFFF8(-8)
2.the 2th field is the offset of this_ptr from the virtual base class, it always not big, so set the default = 0x10000

Args:
	seg: segment address
'''
def find_vbtable_msvc(seg):
	seg_start = idc.SegStart(seg)
	seg_end = idc.SegEnd(seg)
	cur_addr = seg
	while cur_addr < seg_end - 4:
		data = idc.Dword(cur_addr)
		# data is vftable_ptr offset
		# 为0代表该类没有虚函数
		if (data == 0xFFFFFFF8) or (data == 0):                        #32 is 0xFFFFFFFC
			xrefs = list(idautils.XrefsTo(cur_addr))
			if len(xrefs) != 0:
				data2 = idc.Dword(cur_addr+4)
				# data2 is vbase offset
				if 8 < data2 < 0x10000:
					vbtable_list[hex(cur_addr).strip("L")] = hex(data2).strip("L")

		cur_addr += 4

def search_vbtable_list_msvc():
	for seg in idautils.Segments():
		if idc.SegName(seg) in vbtable_section_names:
			find_vbtable_msvc(seg)
'''
MSVC: idata段系统函数符号搜索
'''
'''
MSVC: Search system function symbol in idata segment 
'''
def scan_idata_msvc(arch=64):
	global symbol_list
	addr = idata_start
	while addr <= idata_end:
		import_name = idc.Name(addr)
		if not import_name:
			if arch == 64:
				addr += 8
			else:
				addr += 4
			continue
		symbol_list[hex(addr).strip("L")] = import_name
		if arch == 64:
			addr += 8
		else:
			addr += 4

	# 获取rdata中的系统调用:__guard_check_icall_fptr,__guard_dispatch_icall_fptr
	import_name = idc.Name(rdata_start)
	if import_name == "__guard_check_icall_fptr":
		symbol_list[hex(rdata_start).strip("L")] = import_name
	if arch == 64:
		addr = rdata_start + 8
	else:
		addr = rdata_start + 4
	import_name = idc.Name(addr)
	if import_name == "__guard_dispatch_icall_fptr":
		symbol_list[hex(addr).strip("L")] = import_name

hasdrr = 0
hasgot = 0
hasplt = 0
for seg in idautils.Segments():
	if idc.SegName(seg) == '.text':
		text_start = idc.SegStart(seg)
		text_end = idc.SegEnd(seg)
	if idc.SegName(seg) == '.pdata':
		pdata_start = idc.SegStart(seg)
		pdata_end = idc.SegEnd(seg)
	if idc.SegName(seg) == '.idata':
		idata_start = idc.SegStart(seg)
		idata_end = idc.SegEnd(seg)
	if idc.SegName(seg) == '.rdata':
		rdata_start = idc.SegStart(seg)
		rdata_end = idc.SegEnd(seg)
	if idc.SegName(seg) == '.data.rel.ro':
		drrdata_start = idc.SegStart(seg)
		drrdata_end = idc.SegEnd(seg)
		hasdrr = 1
	if idc.SegName(seg) == '.rodata':
		rodata_start = idc.SegStart(seg)
		rodata_end = idc.SegEnd(seg)
	if idc.SegName(seg) == 'extern':
		extern_start = idc.SegStart(seg)
		extern_end = idc.SegEnd(seg)
	if idc.SegName(seg) == '.got':
		got_start = idc.SegStart(seg)
		got_end = idc.SegEnd(seg)
		hasgot = 1
	if idc.SegName(seg) == '.plt':
		plt_start = idc.SegStart(seg)
		plt_end = idc.SegEnd(seg)
		hasplt = 1

'''
MSVC主函数
执行流程：
	1.搜索vftable
	2.搜索vbtable
	3.搜索析构函数
	4.将析构函数相关函数加入列表，并执行启发式搜索构造函数
	5.搜索系统函数符号
'''
'''
MSVC main function
Implementation process:
	1. Search for vftable
	2. Search for vbtable
	3. Search the destructor
	4. Add the destructor related functions to the list and execute the heuristic search constructor
	5. Search the system function symbol
'''
def main_msvc():
	start = time.time()
	search_vftable_list_msvc()
	search_vbtable_list_msvc()
	for vftable in vftable_list:
		vftables_addr.append(int(vftable,16))
	#print vftable_list
	end = time.time()
	#print vbtable_list     
	print "[+]log: Extract vftable and vbtable completion. Time:%fs" % (end-start)
	# check every vftable dtor
	start = time.time()
	check_dtor_msvc()
	end = time.time()
	print "[+]log: Search dtor completion. Time:%fs" % (end-start)
	#for vftable in vftable_list:          
	#	if "not_vftable" in vftable_list[vftable]:
	#		if vftable_list[vftable]["not_vftable"] == 1:
	#			continue
	#	print vftable,vftable_list[vftable]     
	#print "vftable_list num:"
	#print len(vftable_list)
	start = time.time()
	delete_xref_msvc()
	for delete in delete_xref_list:
		print hex(delete)
	#print "delete_xref_list num"
	#print len(delete_xref_list)
	fast_check_ctor_msvc(pdb=1)
	end = time.time()
	#for ctor in ctor_list:
	#	print ctor,ctor_list[ctor]
	#print "ctor_list num:"
	#print len(ctor_list)  
	print "[+]log: Search ctor completion. Time:%fs" % (end-start)
	#overwrite_analysis()
	#for ctor in ctor_list:
	#   print ctor,ctor_list[ctor]
	vftable_file = open("vftable","w")
	vftable_jsonstr = json.dumps(vftable_list)  
	vftable_file.write(vftable_jsonstr)
	vftable_file.close()

	vbtable_file = open("vbtable","w")
	vbtable_jsonstr = json.dumps(vbtable_list)  
	vbtable_file.write(vbtable_jsonstr)
	vbtable_file.close()

	ctor_file = open("ctor","w")
	ctor_jsonstr = json.dumps(ctor_list)    
	ctor_file.write(ctor_jsonstr)
	ctor_file.close()

	scan_idata_msvc(arch=64)

	symbol_file = open("symbol","w")
	symbol_jsonstr = json.dumps(symbol_list)
	symbol_file.write(symbol_jsonstr)
	symbol_file.close()

def search_vftable_list_gcc():
	for seg in idautils.Segments():
		if idc.SegName(seg) in vftable_section_names:
			find_vftable_gcc(seg)


'''
GCC:寻找vftable, 将其加入vftable_list中

1.寻找RTTI,RTTI的第一项有交叉引用，第二项在rodata段
2.rttiptr上一项<=0,下一项为虚函数或者为0 && data在代码段

参数： 
	seg： 段起始地址

'''
''' 
GCC: Search vftable, and add it into vftable_list

1. Look for RTTI, the first item of RTTI has a cross reference, the second item is in the rodata section
2. The previous item of rttiptr <=0, the next item is a virtual function or 0 && data in .text

Args:
	seg: segment address

'''
def find_vftable_gcc(seg):
	seg_start = idc.SegStart(seg)
	seg_end = idc.SegEnd(seg)
	cur_addr = seg
	cur_vftable_start = ""
	last_add_addr = 0
	
	while cur_addr <= seg_end - 8:                   #32 is 4
		data = idc.Qword(cur_addr)                  #32 is Dword

		hasRtti = 0
		# 寻找他的rtti,第一项有交叉引用，第二项在rodata段，为类名 (hasdrr为.data.rel.ro存在)
		rttiptr = idc.Qword(cur_addr)
		if  (rodata_start <= rttiptr < rodata_end) or ((hasdrr == 1) and (drrdata_start <= rttiptr < drrdata_end)) :
			rttixrefs = list(idautils.XrefsTo(rttiptr))
			if len(rttixrefs) != 0:
				nameptr = idc.Qword(rttiptr+8)
				if rodata_start <= nameptr < rodata_end:
					hasRtti = 1
					# rttiptr上一项<=0,下一项为虚函数或者为0
					if (struct.unpack('q',struct.pack('Q',idc.Qword(cur_addr-8)))[0]<=0) and ((text_start <= idc.Qword(cur_addr+8) < text_end) or (idc.Qword(cur_addr+8) == 0)):
						cur_vftable_start = hex(cur_addr+8).strip("L")
						vftable_list[cur_vftable_start] = dict()
						vftable_list[cur_vftable_start]["functions"] = list()

						vftable_symbol = idc.GetOpnd(cur_addr,0)
						if len(vftable_symbol) > 1:
							vftable_symbol = re.sub(r'^offset ','',vftable_symbol)
							vftable_list[cur_vftable_start]["symbol"] = vftable_symbol

						# 将vbase_offset添加到vftable中
						vbase_offset_addr = cur_addr - 0x10
						while (0< idc.Qword(vbase_offset_addr) < 0x1000) and (idc.Qword(vbase_offset_addr)%8 == 0):
							if "vbase_offset" in vftable_list[cur_vftable_start]:
								vftable_list[cur_vftable_start]["vbase_offset"].append(idc.Qword(vbase_offset_addr))
							else:
								vftable_list[cur_vftable_start]["vbase_offset"] = list()
								vftable_list[cur_vftable_start]["vbase_offset"].append(idc.Qword(vbase_offset_addr))
							vbase_offset_addr = vbase_offset_addr - 8
		# 若找到rttiptr，添加的函数为0（只有前两项），函数在代码段上，函数在extern段中
		if len(cur_vftable_start) != 0:
			if ((data==0) and (len(vftable_list[cur_vftable_start]["functions"])<2)) or (text_start <= data < text_end) or (extern_start <= data < extern_end):
				vftable_list[cur_vftable_start]["functions"].append(hex(data).strip("L"))
			else:
				cur_vftable_start == ""

		cur_addr += 8  
		

def search_VTT_list_gcc():
	for seg in idautils.Segments():
		if idc.SegName(seg) in VTT_section_names:
			find_VTT_gcc(seg)


'''
GCC：寻找VTT

1.VTT在只读段
2.通过析构函数确定VTT的边界，每个派生类的VTT的vftable都分布在VTT的开头和结尾。

参数：
	seg：段地址
'''
'''
GCC: Search VTT

1. VTT in read-only segment
2. Determine the boundary of VTT through the destructor. The Vftable of each derived class is distributed at the beginning and end of VTT.

Args:
	seg: segment address
'''
def find_VTT_gcc(seg):
	seg_start = idc.SegStart(seg)
	seg_end = idc.SegEnd(seg)
	cur_addr = seg
	cur_VTT_start = ""
	last_dtor = -1
	VTT_end = 0
	while cur_addr <= seg_end - 8:                   #32 is 4
		data = idc.Qword(cur_addr)                  #32 is Dword
		data_str = hex(data).strip("L")

		if data_str in vftable_list:
			if last_dtor == -1:
				last_dtor = vftable_list[data_str]["dtor"]
				cur_VTT_start = hex(cur_addr).strip("L")
				VTT_list[cur_VTT_start] = dict()
				VTT_list[cur_VTT_start]["vftable"] =list()
				VTT_list[cur_VTT_start]["vftable"].append(data_str) 
				addr_str = hex(cur_addr).strip("L")
				VTT_list[cur_VTT_start]["addr"] =list()
				VTT_list[cur_VTT_start]["addr"].append(addr_str) 
			else:
				VTT_list[cur_VTT_start]["vftable"].append(data_str)
				addr_str = hex(cur_addr).strip("L")
				VTT_list[cur_VTT_start]["addr"].append(addr_str) 
				cur_dtor = vftable_list[data_str]["dtor"]
				if cur_dtor == last_dtor:
					VTT_end = 1
				if VTT_end == 1:
					next_data = idc.Qword(cur_addr+8)
					next_data_str = hex(next_data).strip("L")			 				
					if next_data_str in vftable_list:
						next_dtor = vftable_list[next_data_str]["dtor"]
						if next_dtor != last_dtor:
							last_dtor = -1
							VTT_end = 0
							cur_VTT_start = ""
					else:
						last_dtor = -1
						VTT_end = 0
						cur_VTT_start = ""
		cur_addr += 8 

'''
GCC: 搜索系统函数符号
'''
'''
GCC: Search system function symbol
'''
def scan_gcc_sys_symbol(arch=64):
	global symbol_list

	for seg in idautils.Segments():
		if idc.SegName(seg) in ['.got','.got.plt','extern']:
			start = idc.SegStart(seg)
			end = idc.SegEnd(seg)
			addr = start
			while addr <= end:
				if idc.SegName(seg) == 'extern':
					import_name = idc.Name(addr)
				else:
					import_name = idc.GetOpnd(addr,0)
					import_name = re.sub(r'^offset ','',import_name)
				if (not import_name) or (import_name == "0"):
					if arch == 64:
						addr += 8
					else:
						addr += 4
					continue
				symbol_list[hex(addr).strip("L")] = import_name
				if arch == 64:
					addr += 8
				else:
					addr += 4		


	

def main_gcc():
	start = time.time()
	search_vftable_list_gcc()
	for vftable in vftable_list:
		vftables_addr.append(int(vftable,16))
	
	end = time.time()
	#print vbtable_list     
	print "[+]log: Extract vftable completion. Time:%fs" % (end-start)
	# check every vftable dtor
	start = time.time()
	check_dtor_gcc()
	end = time.time()

	print "[+]log: Search dtor completion. Time:%fs" % (end-start)
	#for vftable in vftable_list:          
	#	if "not_vftable" in vftable_list[vftable]:
	#		if vftable_list[vftable]["not_vftable"] == 1:
	#			continue
	#	print vftable,vftable_list[vftable]     
	#print "vftable_list num:"
	#print len(vftable_list)
	
	start = time.time()
	search_VTT_list_gcc()
	end = time.time()
	print "[+]log: Search VTT completion. Time:%fs" % (end-start) 
	start = time.time()
	delete_xref_gcc()
	print "[+]log: delete_xref completion"
	#for delete in delete_xref_list:
	#	print hex(delete).strip("L")
	#print "delete_xref_list num"
	#print len(delete_xref_list)
	fast_check_ctor_gcc(pdb=1)
	end = time.time()
	#for ctor in ctor_list:
	#	print ctor,ctor_list[ctor]
	
	for vftable in vftable_list:
		print vftable,vftable_list[vftable]
	
	print "[+]log: Search ctor completion. Time:%fs" % (end-start)

	


	print "[*]log: The number of vftable:%d" % len(vftable_list)
	print "[*]log: The number of VTT:%d" % len(VTT_list)
	print "[*]log: The number of ctor:%d" % len(ctor_list)

	vftable_file = open("vftable","w")
	vftable_jsonstr = json.dumps(vftable_list)  
	vftable_file.write(vftable_jsonstr)
	vftable_file.close()

	VTT_file = open("VTT","w")
	VTT_jsonstr = json.dumps(VTT_list)  
	VTT_file.write(VTT_jsonstr)
	VTT_file.close()

	ctor_file = open("ctor","w")
	ctor_jsonstr = json.dumps(ctor_list)    
	ctor_file.write(ctor_jsonstr)
	ctor_file.close()

	scan_gcc_sys_symbol(arch=64)

	symbol_file = open("symbol","w")
	symbol_jsonstr = json.dumps(symbol_list)
	symbol_file.write(symbol_jsonstr)
	symbol_file.close()


def main(filetype):
	if filetype == "PE":
		main_msvc()
	elif filetype == "ELF":
		main_gcc()


if __name__ == '__main__':
	start = time.time()
	main()
	#main_gcc()
	#main_msvc()
	end = time.time()
	print "time:%fs" % (end-start) 