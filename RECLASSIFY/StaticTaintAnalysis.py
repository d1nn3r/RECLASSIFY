#!/usr/bin/env python
#-*-coding:utf-8-*-
'''
Author:d1nn3r
'''
import angr
import sys
import pyvex
import cfg
import random
import struct

'''
静态污点分析

成员变量：
	proj：angr程序实例
	cfg：构造函数和析构函数及其相关函数的CFG实例
	vftable_list：vftable列表
		数据格式：
			vftable_addr: vftable地址，dict
				functions：vftable包含函数地址，list
				rtti：RTTI地址，不存在为0
				jmp_dtor：跳转析构函数地址，不存在为0
				dtor：析构函数地址
				symbol：符号，若没有该项不存在
				has_purecall：若存在纯虚函数则为1，否则该项不存在
				has_correlation：相关性结果，若为1则是相关性分析得到的，若没有该项不存在
				not_vftable：若为非vftable则为1，否则该项不存在，目前该项已废弃
				virtual_inherit：若存在虚继承则该项为1，否则该项不存在
				vbtable：若virtual_inherit为1则记录相应的vbtable，否则该项不存在
				xref:交叉引用分析结果，若为1则是通过交叉引用分析得到的，若没有该项不存在
				vbase_offset：虚基类偏移，GCC分析中才有，将vftable上的OffsetToVbase字段的结果保存在这里，list
	vbtable_list：vbtable列表
		数据格式：
			vbtable_addr: offset
			vbtable地址：虚基类偏移
	VTT_list：VTT列表
		数据格式：
			VTT_addr：VTT地址，dict
				addr：subVTT地址，list
				vftable：vftable地址，list，与addr相对应
	ctor_list：对象内存布局列表，初始为构造函数
		数据格式：
			ctor_dtor_addr：构造函数或者析构函数地址，dict
				this_offset：对象内存布局，dict
					offset：对象内存布局偏移，dict
						value：对象内存布局的内容（vftable，vbase，vbtable，var），
							vftable为list，每项为元祖（vftable地址，vftable覆写顺序）
							vbase为list，每项为元祖（vftable地址，vftable覆写顺序），虚基类标签
							vbtable为vbtable地址
							var为变量值
						attribute：对象内存布局属性，有四种：vftable，vbase，vbtable，var与value对应
				new_addr：对象对应的new()信息，若是静态对象该项不存在，dict
					hierarchy：覆写操作与new()所在层级关系，若为1则为构造函数完全内联情况，否则为0
					addr：调用new()的指令地址
					func_addr：调用new()的函数地址
				multi_class：若检测到有多个对象，则可能为构造函数完全内联，值为1，否则该项不存在
				no_new：若检测到为静态对象，则值为1，否则该项不存在
				unknow：若检测到未知错误情况，则值为1，否则该项不存在
	filetype：文件类型，目前支持PE和ELF文件类型
	taint_register：寄存器污点
	taint_rsp：栈上变量污点
	vftable_num：覆写顺序
	flag： 调试模式控制变量，默认为0
	symbol_list：系统函数符号表
		数据格式：
			addr: symbol
			地址：符号
	new_list：new()符号表
	multi_ctor_list：一个构造函数中具有多个对象的对象内存布局列表
'''
'''
Static taint analysis

Members：
	proj: angr program instance
	cfg: instance of CFG of constructor, destructor and related functions
	vftable_list: vftable list
		Data Format:
			vftable_addr: vftable address, dict
			functions: vftable contains function addresses, list
			rtti: RTTI address, 0 if not present
			jmp_dtor: jump destructor address, if it does not exist, it is 0
			dtor: destructor address
			symbol: symbol, if there is no item does not exist
			has_purecall: 1 if there is a pure virtual function, otherwise the item does not exist
			has_correlation: Correlation result, if it is 1, it is obtained by correlation analysis, if there is no item does not exist
			not_vftable: 1 if it is non-vftable, otherwise the item does not exist, and the item is currently obsolete
			virtual_inherit: If there is virtual inheritance, the item is 1, otherwise the item does not exist
			vbtable: If virtual_inherit is 1, record the corresponding vbtable, otherwise the item does not exist
			xref: cross reference analysis result, if it is 1, it is obtained through cross reference analysis, if there is no item does not exist
			vbase_offset: virtual base class offset, only available in GCC analysis, save the result of the OffsetToVbase field on vftable here, list
	vbtable_list: vbtable list
		Data Format:
			vbtable_addr: offset
			vbtable address: virtual base class offset
	VTT_list: VTT list
		Data Format:
			VTT_addr: VTT address, dict
				addr: subVTT address, list
				vftable: vftable address, list, corresponding to addr
	ctor_list: object memory layout list, initially as a constructor
		Data Format:
			ctor_dtor_addr: constructor or destructor address, dict
				this_offset: object memory layout, dict
					offset: Object memory layout offset, dict
						value: the content of the object memory layout (vftable, vbase, vbtable, var),
							vftable is a list, and each item is a ancestor (vftable address, vftable override order)
							vbase is a list, each item is a ancestor (vftable address, vftable override order), virtual base class label
							vbtable is the vbtable address
							var is the variable value
						attribute: Object memory layout attributes, there are four types: vftable, vbase, vbtable, var and value corresponding
				new_addr: the new() information corresponding to the object. If the item does not exist for a static object, dict
					hierarchy: the hierarchical relationship between the overwrite operation and new(), if it is 1, it means the constructor is completely inline, otherwise it is 0
					addr: instruction address for calling new()
					func_addr: function address to call new()
				multi_class: If multiple objects are detected, the constructor may be completely inline, with a value of 1, otherwise the item does not exist
				no_new: if detected as a static object, the value is 1, otherwise the item does not exist
				unknow: If an unknown error condition is detected, the value is 1, otherwise the item does not exist
	filetype: file type, currently supports PE and ELF file types
	taint_register: register taint
	taint_rsp: variable taint on the stack
	vftable_num: Overwrite order
	flag: Debugging mode control variable, default is 0
	symbol_list: symbol table of system functions
		Data Format:
			addr: symbol
			Address: Symbol
	new_list: new() symbol table
	multi_ctor_list: list of object memory layouts with multiple objects in one constructor
'''
class StaticTaintAnalysis:
	def __init__(self,proj,cfg,vftable_list,vbtable_list,VTT_list,ctor_list,symbol_list,filetype):
		self.proj = proj
		self.cfg = cfg
		self.vftable_list = vftable_list
		self.vbtable_list = vbtable_list
		self.VTT_list = VTT_list
		self.ctor_list = ctor_list    
		self.filetype = filetype    
		self.taint_register = None        #记录寄存器污点
		self.taint_rsp = None             #记录栈上变量污点
		self.vftable_num = None           #记录覆写顺序
		self.flag = 0
		self.symbol_list = symbol_list
		self.new_list = []                #记录new operation地址
		self.multi_ctor_list = {}

		self.analysis()

	'''
	分析起始函数

	1.预分析：记录new操作地址
	2.覆写分析：
		起始污点为this指针，指为0，若构造函数完全内联则this指针为rax，其他情况下PE文件this指针为rcx，ELF文件this指针为rdi
	3.后续分析：
		（1）分析拥有多个对象的构造函数
		（2）若vftable不存在对应的构造函数，则进行析构函数分析
		（3）删除里面的异常处理等vftable（不是该ctor的vftbale）
		（4）GCC：当派生类只直接继承虚基类，并没有子类，识别出其中的虚基类
	'''	
	'''
	Analysis start function

	1. Pre-analysis: record the new operation address
	2. Overwrite analysis:
		The starting taint is this pointer, which is 0. If the constructor is completely inlined, this pointer is rax. In other cases, this pointer of PE file is rcx, and this pointer of ELF file is rdi.
	3. Follow-up analysis:
		(1) Analysis of the constructor with multiple objects
		(2) If there is no corresponding constructor in vftable, then destructor analysis
		(3) Delete the exception handling etc. vftable (not the ctor's vftbale)
		(4) GCC: When the derived class only directly inherits the virtual base class and has no subclasses, the virtual base class is identified
	'''
	def analysis(self):
		self.pre_analysis()
		ctor_count = len(self.ctor_list)
		for i,ctor in enumerate(self.ctor_list):
			self.taint_register = {}
			self.taint_rsp = {}
			self.taint_rsp[ctor] = {}
			self.vftable_num = 1
			# 0 new operation与ctor在同一层
			if ("hierarchy" in self.ctor_list[ctor]["new_addr"]) and (self.ctor_list[ctor]["new_addr"]["hierarchy"] == 0):
				new_addr = int(self.ctor_list[ctor]["new_addr"]["addr"],16)
				block = self.proj.factory.block(new_addr)
				insn = block.capstone.insns[-1]
				block_addr = insn.address + insn.size


				# rax = offset 16
				this = 16
				self.taint_register[this] = 0
				self.overwrite_analysis(ctor,ctor,block_addr,this,0)
			# -1 new operation在ctor的上一层
			# 1 new operation和ctor在同一个函数的不同子函数中
			else:
				if self.filetype == "PE":
					# rcx = offset 24
					this = 24 
				elif self.filetype == "ELF":
					# rdi == offset 72
					this = 72
				self.taint_register[this] = 0   
				self.overwrite_analysis(ctor,ctor,int(ctor,16),this,0)
			print "%s/%s %s static_taint_analysis ctor completion" % (i+1,ctor_count,ctor)

		self.post_analysis()
					
	'''
	覆写分析

	参数：
		ctor: 构造函数或者析构函数地址
		function_addr_str：函数地址
		block_addr：基本块地址
		this：this指针
		hierarchy：递归次数，代表函数层级
	'''
	'''
	Overwrite analysis

	Args:
		ctor: constructor or destructor address
		function_addr_str: function address
		block_addr: basic block address
		this: this pointer
		hierarchy: Recursion times, representing function hierarchy
	'''
	def overwrite_analysis(self,ctor,function_addr_str,block_addr,this,hierarchy):
		if hierarchy >=5:
			return
		this_hierarchy = hierarchy
		'''
		# TODO: MpEngine.dll bug PEFileWriter与PEFileReader vbtable偏移不一样
		if function_addr_str == "0x75a13a10c":
			return
		# TODO: QuantLib.dll 不知道哪里的问题无限循环了
		if function_addr_str == "0x180207940":
			return
		'''
		traced_block = dict()

		while 1:
			#print function_addr_str,hex(block_addr)
			loop_flag = 0
			if block_addr in traced_block:
				#print hex(block_addr)
				loop_flag = 1
				traced_block[block_addr] += 1
				if traced_block[block_addr] >= 10:
					loop_flag = 2
				# 防止无限循环
				if traced_block[block_addr] >= 1000:
					print "function %s time out!!break. block addr:%s" % (function_addr_str,hex(block_addr))
					return
			else:
				traced_block[block_addr] = 0
			
				
			# 排除只有jmp的系统调用函数
			# jmp cs:__imp__RTDynamicCast
			if function_addr_str not in self.cfg.functions:
				b_addr = int(function_addr_str,16)
				block = self.proj.factory.block(b_addr)
				if (len(block.capstone.insns) == 1) and (block.capstone.insns[-1].insn.insn_name() == "jmp"):
					return

			# 若存在没有cfg的情况，即前面有间接跳转，如jmp rcx等
			if block_addr not in self.cfg.functions[function_addr_str].nodes:
				start_points = []
				start_points.append(int(function_addr_str,16))
				# 单独处理那一个函数，改为从malloc下一个block开始生成cfg
				mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1,is_one=True,target_block_addr=block_addr)
				for function in mycfg.functions:
					self.cfg.functions[function] = mycfg.functions[function]

			block = self.cfg.functions[function_addr_str].nodes[block_addr]["block"]

			irsb = block.vex

			double_vbtable = False
			taint_tmp = {}
			for i,stmt in enumerate(irsb.statements):
				# reg->tmp
				# tmp->tmp
				if isinstance(stmt,pyvex.stmt.WrTmp):
					expr = stmt.data
					# reg->tmp
					if isinstance(expr,pyvex.expr.Get):
						# 污点传播
						if expr.offset in self.taint_register:
							taint_tmp[stmt.tmp] = self.taint_register[expr.offset]
						else:
							# 污点消除
							if stmt.tmp in taint_tmp:
								del taint_tmp[stmt.tmp]

					# tmp->tmp
					elif isinstance(expr,pyvex.expr.Binop):
						# tmp+const
						if expr.op == "Iop_Add64":
							child_expressions = expr.child_expressions
							# 排除以下情况：
							# t3 = Add64(0x0000000000000000,t2) 
							if isinstance(child_expressions[0],pyvex.expr.RdTmp):
								tmp = child_expressions[0].tmp
								if isinstance(child_expressions[1],pyvex.expr.RdTmp):
									tmp2 = child_expressions[1].tmp
									# 污点传播
									if (tmp in taint_tmp) and (tmp2 in taint_tmp):
										# 虚基类
										if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):
											taint_tmp[stmt.tmp] = (taint_tmp[tmp][0] + taint_tmp[tmp2],"vbase")
										elif isinstance(taint_tmp[tmp2],tuple) and (taint_tmp[tmp2][1] == "vbase"):
											taint_tmp[stmt.tmp] = (taint_tmp[tmp2][0] + taint_tmp[tmp],"vbase")
										else:
											if isinstance(taint_tmp[tmp],int) and isinstance(taint_tmp[tmp2],int):
												taint_tmp[stmt.tmp] = taint_tmp[tmp] + taint_tmp[tmp2]


									else:
										# 污点消除
										if stmt.tmp in taint_tmp:
											del taint_tmp[stmt.tmp]
								else:
									const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
									# 污点传播
									if tmp in taint_tmp:
										# 从vbtable获取虚基类偏移
										if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbtable"):
											taint_tmp[stmt.tmp] = (taint_tmp[tmp][0],"vbase")
										else:
											# 虚基类
											if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):
												# 排除vftable list的错误传播
												if isinstance(taint_tmp[tmp][0],int) or isinstance(taint_tmp[tmp][0],long):
													taint_tmp[stmt.tmp] = (taint_tmp[tmp][0] + const,"vbase")
												else:
													del taint_tmp[tmp]
											else:
												if isinstance(taint_tmp[tmp],int) or isinstance(taint_tmp[tmp],long):
													taint_tmp[stmt.tmp] = taint_tmp[tmp] + const
												elif (self.filetype == "ELF") and isinstance(taint_tmp[tmp],str):
													find = 0
													for VTT in self.VTT_list:
														if taint_tmp[tmp] in self.VTT_list[VTT]["addr"]:
															find = 1
															break
													if find == 1:
														taint_tmp[stmt.tmp] = hex(int(taint_tmp[tmp],16) + const).strip("L")
													else:
														del taint_tmp[tmp]
												else:
													del taint_tmp[tmp]
												
									else:
										# 污点消除
										if stmt.tmp in taint_tmp:
											del taint_tmp[stmt.tmp]
						elif expr.op == "Iop_Sub64":

							child_expressions = expr.child_expressions

							# 排除以下情况：
							# t3 = Sub64(0x0000000000000000,t2) -> neg rax  取反
							if isinstance(child_expressions[0],pyvex.expr.RdTmp):
								tmp = child_expressions[0].tmp
								# 污点传播
								if tmp in taint_tmp:
									# 40 | ------ IMark(0x154a, 3, 0) ------
									# 41 | t48 = LDle:I64(t47)
									# 42 | ------ IMark(0x154d, 4, 0) ------
									# 43 | t13 = Sub64(t48,0x0000000000000018)  <-----------
									# 44 | PUT(pc) = 0x0000000000001551
									# eg. vftable-0x18
									if self.filetype == "ELF" and isinstance(irsb.statements[i-2],pyvex.stmt.WrTmp) and isinstance(irsb.statements[i-2].data,pyvex.expr.Load):
										vftable = taint_tmp[tmp]
										for VTT in self.VTT_list:
											if vftable in self.VTT_list[VTT]["vftable"]:
												const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
												vftable_addr = int(vftable,16)
												vbase_offset_addr = vftable_addr - const
												taint_tmp[stmt.tmp] = (vbase_offset_addr,"VTT")
												break
									elif isinstance(child_expressions[1],pyvex.expr.Const):
										const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]  
										# TODO: 因为跳过了间接函数调用，有些寄存器可能没有消除污点，消除污点是否会带来别的影响？
										# cryptopp.dll  0x429A060E                 sub     rbx, 1
										# ([('0x42a0d2b0', 10)], 'vbtable') - 1
										if isinstance(taint_tmp[tmp],tuple):
											del taint_tmp[tmp]
										else:                           
											if isinstance(taint_tmp[tmp],int) or isinstance(taint_tmp[tmp],long):
												taint_tmp[stmt.tmp] = taint_tmp[tmp] - const
											else:
												del taint_tmp[tmp]
								else:
									# 污点消除
									if stmt.tmp in taint_tmp:
										del taint_tmp[stmt.tmp]
						else:
							# t28 = CmpEQ8(t30,t29)
							if stmt.tmp in taint_tmp:
								del taint_tmp[stmt.tmp]
					# Load->tmp
					elif isinstance(expr,pyvex.expr.Load):
						child_expressions = expr.child_expressions
						if len(child_expressions)==1:
							if isinstance(child_expressions[0],pyvex.expr.RdTmp):
								tmp = child_expressions[0].tmp
								if expr.type == "Ity_I64":
									# 污点传播
									if tmp in taint_tmp:
										if self.filetype == "ELF":
											# 获取vbase_offset
											if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "VTT"):
												state = self.proj.factory.blank_state()
												vbase_offset_addr = taint_tmp[tmp][0]
												bv = state.mem[vbase_offset_addr].uint64_t.resolved
												vbase_offset = bv.args[0]
												taint_tmp[stmt.tmp] = (vbase_offset,"vbase")
											else:
												if isinstance(taint_tmp[tmp],str):
													offset_str = taint_tmp[tmp]
												else:
													offset_str = hex(taint_tmp[tmp]).strip("L")
												# 从内存布局中获取vftable
												if (offset_str in self.ctor_list[ctor]["this_offset"]) and (self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] != "var") and (isinstance(self.ctor_list[ctor]["this_offset"][offset_str]["value"],list)):
													vftable = self.ctor_list[ctor]["this_offset"][offset_str]["value"][-1][0]
													taint_tmp[stmt.tmp] = vftable
												else:
													addr = taint_tmp[tmp]
													# 从VTT中查找vftable
													vftable = self.getVftableFromVTT(addr)
													if vftable != None:
														taint_tmp[stmt.tmp] = vftable
										# 忽略带vbase信息的元组
										if (not isinstance(taint_tmp[tmp],int) ) and (not isinstance(taint_tmp[tmp],long) ):
											del taint_tmp[tmp]
										else:
											offset_str = hex(taint_tmp[tmp]).strip("L")

										
											if offset_str in self.ctor_list[ctor]["this_offset"]:
												if self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] == "var":
													# 将var的值赋值
													taint_tmp[stmt.tmp] = self.ctor_list[ctor]["this_offset"][offset_str]["value"]

												elif self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] == "vbtable":
													# 将vbtable的地址赋值
													taint_tmp[stmt.tmp] = (self.ctor_list[ctor]["this_offset"][offset_str]["value"],"vbtable")
											# TODO:目前只处理的hierachy = -1的情况,只扫描new operation 下面的那个block
											elif ("new_addr" in self.ctor_list[ctor]) and (self.ctor_list[ctor]["new_addr"]["hierarchy"] == -1) and isinstance(irsb.statements[i+1],pyvex.stmt.Put):
												new_addr = int(self.ctor_list[ctor]["new_addr"]["addr"],16)
												insn = self.proj.factory.block(new_addr).capstone.insns[0].insn
												new_next_addr = insn.address + insn.size
												# 寻找和vftable相关的内存布局
												self.handle_new_next_block(ctor,new_next_addr,self.ctor_list[ctor]["new_addr"]["func_addr"])

												if offset_str in self.ctor_list[ctor]["this_offset"]:
													taint_tmp[stmt.tmp] = self.ctor_list[ctor]["this_offset"][offset_str]["value"]
									else:
										# 从rsp中存储的污点寻找
										rsp_offset = self.is_rsp(function_addr_str,irsb,i,tmp)
										if (rsp_offset != None) and (rsp_offset in self.taint_rsp[function_addr_str]):
											if isinstance(self.taint_rsp[function_addr_str][rsp_offset],list):
												if len(self.taint_rsp[function_addr_str][rsp_offset]) != 0:
													reg_data = self.taint_rsp[function_addr_str][rsp_offset].pop()
											else:
												reg_data = self.taint_rsp[function_addr_str][rsp_offset]

											taint_tmp[stmt.tmp] = reg_data
											# 找到将该临时变量也标记污点，后面的的是利用这个覆写
											taint_tmp[tmp] = reg_data
										# 污点消除
										elif stmt.tmp in taint_tmp:
											del taint_tmp[stmt.tmp]
								elif expr.type == "Ity_I32":
									prev_stmt = irsb.statements[i-1]
									if isinstance(prev_stmt,pyvex.stmt.WrTmp):
										prev_expr = prev_stmt.data
										if isinstance(prev_expr,pyvex.expr.Binop) and (prev_expr.op == "Iop_Add64"):
											prev_child_expressions = prev_expr.child_expressions
											# 只有Add(tmp,0x4)的采取操作  ->  取vbtable中虚基类的偏移
											if isinstance(prev_child_expressions[1],pyvex.expr.Const) and (struct.unpack('q',struct.pack('Q',prev_child_expressions[1].con.value))[0] ==4):
												# 污点传播
												if tmp in taint_tmp:
													# 从vbtable中取出偏移
													if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):
														if taint_tmp[tmp][0] in self.vbtable_list:
															taint_tmp[stmt.tmp] = (int(self.vbtable_list[taint_tmp[tmp][0]],16),"vbase")
														else:
															del taint_tmp[tmp]

												else:
													# 污点消除
													if stmt.tmp in taint_tmp:
														del taint_tmp[stmt.tmp]

							elif isinstance(child_expressions[0],pyvex.expr.Const):
								got_addr = child_expressions[0].con.value
								if got_addr <= (self.proj.loader.main_bin.mapped_base + self.proj.loader.main_bin.max_addr):
									section_name = self.proj.loader.find_section_containing(got_addr).name
									# 处理got表获取vftable
									if section_name == ".got":
										state = self.proj.factory.blank_state()
										bv = state.mem[got_addr].uint64_t.resolved
										offsetToTop_addr = bv.args[0]
										
										vftable_str = hex(offsetToTop_addr+0x10).strip("L")
										if vftable_str in self.vftable_list:
											taint_tmp[stmt.tmp] = offsetToTop_addr
										else:
											# 有的从OffsetToVbase取
											vftable_str = hex(offsetToTop_addr+0x18).strip("L")
											if vftable_str in self.vftable_list:
												taint_tmp[stmt.tmp] = offsetToTop_addr
											else:
												# 污点消除
												if stmt.tmp in taint_tmp:
													del taint_tmp[stmt.tmp]
									else:
										# 污点消除
										if stmt.tmp in taint_tmp:
											del taint_tmp[stmt.tmp]
						else:
							msg = "[*]error:load expresstions length != 1"
							self.debug(irsb,stmt,ctor,taint_tmp,msg)
					elif isinstance(expr,pyvex.expr.Unop):
						if expr.op == "Iop_32Sto64":
							child_expressions = expr.child_expressions
							if len(child_expressions)==1:
								tmp = child_expressions[0].tmp
								# 污点传播
								if tmp in taint_tmp:
									if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):                                  
										taint_tmp[stmt.tmp] = (taint_tmp[tmp][0],"vbase")
								else:
									# 污点消除
									if stmt.tmp in taint_tmp:
										del taint_tmp[stmt.tmp]
							else:
								msg = "[*]error:load expresstions length != 1"
								self.debug(irsb,stmt,ctor,taint_tmp,msg)

				# const->reg
				# tmp->reg
				elif isinstance(stmt,pyvex.stmt.Put):

					expr = stmt.data
					# 若是rsp，则将self.taint_rsp的值更新
					if stmt.offset == 48:
						tmp = expr.tmp
						prev_stmt = irsb.statements[i-1]
						if isinstance(prev_stmt,pyvex.stmt.WrTmp):
							prev_expr = prev_stmt.data
							if isinstance(prev_expr,pyvex.expr.Binop):
								if prev_expr.op == "Iop_Sub64":
									next_stmt = irsb.statements[i+1]
									next_block_addr = block.capstone.insns[-1].insn.address + block.capstone.insns[-1].insn.size
									# 排除call 产生的push操作
									if isinstance(next_stmt,pyvex.stmt.Store) and isinstance(next_stmt.data,pyvex.expr.Const) and (next_stmt.data.con.value == next_block_addr):
										pass
									else:
										child_expressions = prev_expr.child_expressions
										if isinstance(child_expressions[1],pyvex.expr.Const):
											add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
											new_rsp = {}
											for offset in self.taint_rsp[function_addr_str]:
												new_rsp[offset + add_offset] = self.taint_rsp[function_addr_str][offset]
											self.taint_rsp[function_addr_str] = new_rsp
								
								# 70 | ------ IMark(0x75a33d271, 1, 0) ------
								# 71 | t17 = LDle:I64(t14)
								# 72 | t62 = Add64(t14,0x0000000000000008)
								# 73 | PUT(rsp) = t62              ←——————
								# 74 | PUT(rdi) = t17
								# 75 | PUT(pc) = 0x000000075a33d272
								# pop 操作
								

								elif prev_expr.op == "Iop_Add64":
									if i+2 < len(irsb.statements):
										next_stmt = irsb.statements[i+2]
										# 排除ret的pop操作
										if isinstance(next_stmt,pyvex.stmt.AbiHint) and irsb.jumpkind == "Ijk_Ret":
											pass
										else:
											child_expressions = prev_expr.child_expressions
											if isinstance(child_expressions[1],pyvex.expr.Const):
												add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
												new_rsp = {}
												for offset in self.taint_rsp[function_addr_str]:
													new_rsp[offset - add_offset] = self.taint_rsp[function_addr_str][offset]
												self.taint_rsp[function_addr_str] = new_rsp 
									else:
										child_expressions = prev_expr.child_expressions
										if isinstance(child_expressions[1],pyvex.expr.Const):
											add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
											new_rsp = {}
											for offset in self.taint_rsp[function_addr_str]:
												new_rsp[offset - add_offset] = self.taint_rsp[function_addr_str][offset]
											self.taint_rsp[function_addr_str] = new_rsp 

						# 63 | ------ IMark(0x75a33d26d, 4, 0) ------
						# 64 | t14 = Add64(t57,0x0000000000000030)
						# 65 | PUT(cc_op) = 0x0000000000000004
						# 66 | PUT(cc_dep1) = t57
						# 67 | PUT(cc_dep2) = 0x0000000000000030
						# 68 | PUT(rsp) = t14                  ←——————
						# 69 | PUT(pc) = 0x000000075a33d271
						# 处理add rsp,0x30 和 sub rsp,0x30

						else:
							prev_stmt_1 = irsb.statements[i-1]
							prev_stmt_2 = irsb.statements[i-2]
							prev_stmt_3 = irsb.statements[i-3]
							prev_stmt_4 = irsb.statements[i-4]
							if isinstance(prev_stmt_1,pyvex.stmt.Put) and (prev_stmt_1.offset == 160):
								if isinstance(prev_stmt_2,pyvex.stmt.Put) and (prev_stmt_2.offset == 152):
									if isinstance(prev_stmt_3,pyvex.stmt.Put) and (prev_stmt_3.offset == 144):
										if isinstance(prev_stmt_4,pyvex.stmt.WrTmp):
											prev_expr = prev_stmt_4.data
											if isinstance(prev_expr,pyvex.expr.Binop):
												if prev_expr.op == "Iop_Add64":
													child_expressions = prev_expr.child_expressions
													if isinstance(child_expressions[1],pyvex.expr.Const):
														add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
														new_rsp = {}
														for offset in self.taint_rsp[function_addr_str]:
															new_rsp[offset - add_offset] = self.taint_rsp[function_addr_str][offset]
														self.taint_rsp[function_addr_str] = new_rsp
												elif prev_expr.op == "Iop_Sub64":
													child_expressions = prev_expr.child_expressions
													if isinstance(child_expressions[1],pyvex.expr.Const):
														add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
														new_rsp = {}
														for offset in self.taint_rsp[function_addr_str]:
															new_rsp[offset + add_offset] = self.taint_rsp[function_addr_str][offset]
														self.taint_rsp[function_addr_str] = new_rsp


					# 03 | t7 = Sub64(t8,0x0000000000000008)
					# 04 | PUT(rsp) = t7
					# 05 | STle(t7) = t0
					# 06 | ------ IMark(0x75a81c176, 4, 0) ------
					# 07 | t2 = Sub64(t7,0x0000000000000020)
					# 08 | PUT(cc_op) = 0x0000000000000008
					# 09 | PUT(cc_dep1) = t7
					# 10 | PUT(cc_dep2) = 0x0000000000000020  ←——————
					# 处理sub操作没有赋值rsp的情况
					
					elif stmt.offset == 160:
						if i+1 < len(irsb.statements):					
							next_stmt = irsb.statements[i+1]
							if isinstance(next_stmt,pyvex.stmt.Put) and (next_stmt.offset == 48):
								pass
							else:
								prev_stmt_1 = irsb.statements[i-1]
								prev_stmt_2 = irsb.statements[i-2]
								prev_stmt_3 = irsb.statements[i-3]
								if isinstance(prev_stmt_1,pyvex.stmt.Put) and (prev_stmt_1.offset == 152):
									if isinstance(prev_stmt_2,pyvex.stmt.Put) and (prev_stmt_2.offset == 144):
										if isinstance(prev_stmt_3,pyvex.stmt.WrTmp):
											prev_expr = prev_stmt_3.data
											if isinstance(prev_expr,pyvex.expr.Binop):
												if prev_expr.op == "Iop_Sub64":
													child_expressions = prev_expr.child_expressions
													if isinstance(child_expressions[1],pyvex.expr.Const):
														add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
														tmp = child_expressions[0].tmp
														sub_rsp_flag = 0
														j = i - 4
														while j >= 0:
															search_stmt = irsb.statements[j]
															if isinstance(search_stmt,pyvex.stmt.Put) and (search_stmt.offset == 48):
																if search_stmt.data.tmp == tmp:
																	sub_rsp_flag = 1
																	break
															j = j - 1
														if sub_rsp_flag == 1:
															new_rsp = {}
															for offset in self.taint_rsp[function_addr_str]:
																new_rsp[offset + add_offset] = self.taint_rsp[function_addr_str][offset]
															self.taint_rsp[function_addr_str] = new_rsp

					# tmp->reg
					if isinstance(expr,pyvex.expr.RdTmp):
						tmp = expr.tmp						

						# 污点传播
						if tmp in taint_tmp:
							self.taint_register[stmt.offset] = taint_tmp[tmp]
						else:
							# TODO: 若是rcx，则检查下一条指令是否是call，若是则后向切片寻找rsp offset，并污点标记rcx
							# lea     rcx, [rsp+4E8h+var_2C8] ; this
							# call    ??0StringSource@CryptoPP@@QEAA@PEBD_NPEAVBufferedTransformation@1@@Z
							if stmt.offset == 24:
								j = i + 1
								ins_count = 0
								while j < len(irsb.statements):
									next_stmt = irsb.statements[j]
									
									if isinstance(next_stmt,pyvex.stmt.IMark):
										ins_count += 1
									elif isinstance(next_stmt,pyvex.stmt.AbiHint) and (ins_count == 1):
										k = i - 1
										prev_tmp = tmp
										rcx_offset = 0
										find_rsp_rbp = False
										while k >= 0:
											prev_stmt = irsb.statements[k]
											
											if isinstance(prev_stmt,pyvex.stmt.WrTmp) and (prev_stmt.tmp == prev_tmp):
												prev_expr = prev_stmt.data
												if isinstance(prev_expr,pyvex.expr.Binop):
													if (prev_expr.op == "Iop_Add64") or (prev_expr.op == "Iop_Sub64"):
														child_expressions = prev_expr.child_expressions														
														if isinstance(child_expressions[1],pyvex.expr.Const):
															prev_tmp = child_expressions[0].tmp
															const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
															rcx_offset += const
												elif isinstance(prev_expr,pyvex.expr.Get):

													# rsp | rbp
													if (prev_expr.offset == 48) or (prev_expr.offset == 56):

														find_rsp_rbp = True
														self.taint_register[24] = rcx_offset
														break

											k -= 1
										if find_rsp_rbp:
											break
									j += 1
							else:
								# 从rsp中存储的污点寻找
								rsp_offset = self.is_rsp(function_addr_str,irsb,i,tmp)
								'''
								if function_addr_str == "0x75a33d1c4":
									msg = "[*]is_rsp"
									print "rsp_offset:"+str(rsp_offset)
									self.debug(irsb=irsb,stmt=stmt,msg=msg)
								'''

								if (rsp_offset != None) and (rsp_offset in self.taint_rsp[function_addr_str]):
									if isinstance(self.taint_rsp[function_addr_str][rsp_offset],list):
										if len(self.taint_rsp[function_addr_str][rsp_offset]) != 0:
											reg_data = self.taint_rsp[function_addr_str][rsp_offset].pop()
									else:
										reg_data = self.taint_rsp[function_addr_str][rsp_offset]

									self.taint_register[stmt.offset] = reg_data
									# 找到将该临时变量也标记污点，后面的的是利用这个覆写
									taint_tmp[tmp] = reg_data
								# 污点消除
								elif stmt.offset in self.taint_register:
									del self.taint_register[stmt.offset]
								'''
								# 更新rsp
								if pop == 1:
									new_rsp = {}
									for offset in self.taint_rsp[function_addr_str]:
										new_rsp[offset - 8] = self.taint_rsp[function_addr_str][offset]
									self.taint_rsp[function_addr_str] = new_rsp
								'''

					# const->reg
					elif isinstance(expr,pyvex.expr.Const):
						# 00 | ------ IMark(0x18002fdd6, 7, 0) ------
						# 01 | PUT(rbp) = 0x0000000180041b90
						# 02 | ------ IMark(0x18002fddd, 3, 0) ------
						# NEXT: PUT(rip) = 0x000000018002fde0; Ijk_Boring
						# 后面先call一个函数在进行vftable覆写就会出现这种情况
						const = expr.con.value
						const_str = hex(const).strip("L")
						if const_str in self.vftable_list:
							self.taint_register[stmt.offset] = const_str
						else:
							# 检查VTT赋值
							if self.filetype == "ELF" :
								find = 0
								for VTT in self.VTT_list:
									if const_str in self.VTT_list[VTT]["addr"]:
										self.taint_register[stmt.offset] = const_str
										find = 1
										break
								if find == 0:
									# 污点消除
									if stmt.offset in self.taint_register:
										del self.taint_register[stmt.offset]
							# 污点消除
							elif stmt.offset in self.taint_register:
								del self.taint_register[stmt.offset]

				# vftable_addr->mem[tmp]
				# vbtable_addr->mem[tmp]
				elif isinstance(stmt,pyvex.stmt.Store):
					expr = stmt.data
					# 排除这种指令 rep stosb	byte ptr [rdi], al
					if block.capstone.insns[-1].insn.insn_name() == "stosb":
						pass
					elif isinstance(expr,pyvex.expr.Const):
						const = stmt.data.con.value
						const_str = hex(const).strip("L")
						if const_str in self.vftable_list:
							if isinstance(stmt.addr,pyvex.expr.RdTmp):
								tmp = stmt.addr.tmp
								if tmp in taint_tmp:

									if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):
										offset_str = hex(taint_tmp[tmp][0]).strip("L")
										
										if offset_str in self.ctor_list[ctor]["this_offset"]:
											if self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] == "var":
												self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
												self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vbase"
												self.vftable_num += 1

											else:
												self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vbase"
												self.vftable_num += 1
										else:
											self.ctor_list[ctor]["this_offset"][offset_str] = dict()
											self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
											self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
											self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vbase"
											self.vftable_num += 1
									else:
										# 有些进入其他函数中存在new操作的后面的vftable覆写，忽略这些，后面会有ctor处理
										if not isinstance(taint_tmp[tmp],tuple):
											# 后面又有new操作后的vftable覆写，若是与在ctor函数中则标记为多类
											if isinstance(taint_tmp[tmp],str) and (function_addr_str == ctor) :
											 	self.ctor_list[ctor]["multi_class"] = 1
											 	return
											else:
												# 后面又有new操作后的vftable覆写，忽略
												if isinstance(taint_tmp[tmp],str):
													del taint_tmp[tmp]
												else:
													offset_str = hex(taint_tmp[tmp]).strip("L")
													if offset_str in self.ctor_list[ctor]["this_offset"]:
														if self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] == "var":
															self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
															self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
															self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vftable"
															self.vftable_num += 1
														else:
															if isinstance(self.ctor_list[ctor]["this_offset"][offset_str]["value"],list):
																self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
																self.vftable_num += 1
															else:
																self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
																self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
																self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vftable"
																self.vftable_num += 1

															# VTT 检查，看是否存在虚继承，若是，则将对应内存偏移标记成“vbase”
															if self.filetype == "ELF":
																self.VTT_check(ctor,offset_str,const_str)
													else:
														self.ctor_list[ctor]["this_offset"][offset_str] = dict()
														self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
														self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
														self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vftable"
														self.vftable_num += 1
										else:
											del taint_tmp[tmp]
								else:
									# TODO:排除异常处理的类(因为没有new操作),不知道会不会排除其他的
									# vftable：0x000000075a9e51d0
									# 0x75A265046:   lea     rax, ??_7CHResultExceptionImpl@CommonUtil@@6B@ ; const CommonUtil::CHResultExceptionImpl::`vftable'
									is_not_new = self.is_not_new_opreation(function_addr_str,block.addr,i-1,tmp)
									# TODO：如何处理非new类 -> 放在post_analysis分析
									# 若为非new类，则将vftable放在一起并标注
									if is_not_new == True:
										if function_addr_str == ctor:
											self.ctor_list[ctor]["no_new"] = 1
											return
									else:
										# 检测是否存在构造函数完全内联的情况，存在则先标记上后续再扫描
										if ("new_addr" in self.ctor_list[ctor]) and (self.ctor_list[ctor]["new_addr"]["hierarchy"] == 0) and (ctor == function_addr_str) and (self.is_ctor_multi_class(ctor)):
										 	if function_addr_str == ctor:
											 	self.ctor_list[ctor]["multi_class"] = 1
											 	return
										else:
											# TODO: 存储地址来源于寄存器的间接传递，[eax+0x3000],函数内无法溯源，还有其他的也没做处理
											# 日后需要修正
											if "0x0" in self.ctor_list[ctor]["this_offset"]:
												# TODO: 构造函数完全内联,如何识别多个类 -> 先识别类的数量（通过污点分析各个new与vftable覆写），大于1标记full inline，之后再同一处理 Solved
												# MpEngine:0x75a296ec0
												if isinstance(self.ctor_list[ctor]["this_offset"]["0x0"]["value"],list):
													self.ctor_list[ctor]["this_offset"]["0x0"]["value"].append((const_str,self.vftable_num))
													self.vftable_num += 1
											else:
												self.ctor_list[ctor]["this_offset"]["0x0"] = dict()
												self.ctor_list[ctor]["this_offset"]["0x0"]["value"] = list()
												self.ctor_list[ctor]["this_offset"]["0x0"]["value"].append((const_str,self.vftable_num))
												self.ctor_list[ctor]["this_offset"]["0x0"]["attribute"] = "vftable"
												self.ctor_list[ctor]["unknow"] = 1
												self.vftable_num += 1
										'''
										# 析构函数忽略
										if function_addr_str != "0x75a12bca8":                     
											msg = "[*]error:vftable leave out"
											self.debug(irsb,stmt,ctor,taint_tmp,msg)
										'''
						elif self.filetype == "PE":
							if const_str in self.vbtable_list:
								# 检查重复的vbtable，若存在，则跳过
								find_vbtable = False
								for offset in self.ctor_list[ctor]["this_offset"]:
									if self.ctor_list[ctor]["this_offset"][offset]["attribute"] == "vbtable":
										if const_str == self.ctor_list[ctor]["this_offset"][offset]["value"]:
											find_vbtable = True
											break
								if find_vbtable:
									double_vbtable = True
									break

								if isinstance(stmt.addr,pyvex.expr.RdTmp):
									tmp = stmt.addr.tmp
									if tmp in taint_tmp:
										if isinstance(taint_tmp[tmp],int) or isinstance(taint_tmp[tmp],long):
											offset_str = hex(taint_tmp[tmp]).strip("L")
											if offset_str in self.ctor_list[ctor]["this_offset"]:
												if self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] == "var":
													self.ctor_list[ctor]["this_offset"][offset_str]["value"] = const_str
													self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vbtable"
												else:
													self.ctor_list[ctor]["this_offset"][offset_str]["value"]= const_str
											else:
												self.ctor_list[ctor]["this_offset"][offset_str] = dict()
												self.ctor_list[ctor]["this_offset"][offset_str]["value"]= const_str
												self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vbtable"
										else:
											del taint_tmp[tmp]
									else:
										# 若构造函数遍历时出现new操作和其构造函数，可能无法污点，不过其在后面的ctor_list里有，所以可以略过
										if (function_addr_str != ctor) and (function_addr_str in self.ctor_list):
											pass
										else:
											is_not_new = self.is_not_new_opreation(function_addr_str,block.addr,i-1,tmp)
											# TODO：如何处理非new类 -> 放在post_analysis分析
											# 若为非new类，则将vftable放在一起并标注
											if is_not_new == True:
												if function_addr_str == ctor:
													self.ctor_list[ctor]["no_new"] = 1
													return
											else:
												# TODO:不知道会遗漏什么
												pass
												#msg = "[*]error:vbtable leave out"
												#self.debug(irsb,stmt,ctor,taint_tmp,msg)
					# 一般将寄存器的值保存在栈变量上，保存上下文,一般在函数的第一个基本块
					elif isinstance(expr,pyvex.expr.RdTmp): 
						# 忽略Const [cs:0x100000] = rax 没有作用
						if isinstance(stmt.addr,pyvex.expr.RdTmp):
							data_tmp = expr.tmp
							store_tmp = stmt.addr.tmp
							# 同时被污点标记证明有vftable写入
							if (data_tmp in taint_tmp) and (store_tmp in taint_tmp):
								if self.filetype == "ELF":
									if not isinstance(taint_tmp[data_tmp],str):
										taint_data = hex(taint_tmp[data_tmp]).strip("L")
									else:
										taint_data = taint_tmp[data_tmp]
									if taint_data in self.vftable_list:
										if isinstance(taint_tmp[store_tmp],tuple) and (taint_tmp[store_tmp][1] == "vbase"):
											if isinstance(taint_tmp[store_tmp][0],str):
												offset_str = taint_tmp[store_tmp][0]
											else:
												offset_str = hex(taint_tmp[store_tmp][0]).strip("L")
											if offset_str in self.ctor_list[ctor]["this_offset"]:
												self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((taint_data,self.vftable_num))
												self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vbase"
												self.vftable_num += 1
											else:
												self.ctor_list[ctor]["this_offset"][offset_str] = dict()
												self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
												self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((taint_data,self.vftable_num))
												self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vbase"
												self.vftable_num += 1
										else:
											if isinstance(taint_tmp[store_tmp],str):
												offset_str = taint_tmp[store_tmp]
											else:
												offset_str = hex(taint_tmp[store_tmp]).strip("L")
											const_str = taint_data
											if offset_str in self.ctor_list[ctor]["this_offset"]:
												if self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] == "var":
													self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
													self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
													self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vftable"
													self.vftable_num += 1
												else:
													self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
													self.vftable_num += 1
											else:
												self.ctor_list[ctor]["this_offset"][offset_str] = dict()
												self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
												self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vftable"
												self.vftable_num += 1
								elif isinstance(taint_tmp[store_tmp],int) or isinstance(taint_tmp[store_tmp],long):
									offset_str = hex(taint_tmp[store_tmp]).strip("L")
									const_str = taint_tmp[data_tmp]
									if isinstance(const_str,str):
										if offset_str in self.ctor_list[ctor]["this_offset"]:
											if self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] == "var":
												self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
												self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vftable"
												self.vftable_num += 1
											else:
												self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.vftable_num += 1
										else:
											self.ctor_list[ctor]["this_offset"][offset_str] = dict()
											self.ctor_list[ctor]["this_offset"][offset_str]["value"] = list()
											self.ctor_list[ctor]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
											self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vftable"
											self.vftable_num += 1
									else:
										# TODO:忽略不知道会遗漏什么
										pass
										#msg = "[*]error:const_str not str"
										#self.debug(irsb,stmt,ctor,taint_tmp,msg) 
								else:
									del taint_tmp[store_tmp]
							elif data_tmp in taint_tmp:
								store_tmp = stmt.addr.tmp
								if store_tmp not in taint_tmp:
									# 寻找栈变量偏移
									rsp_offset = self.find_rsp_offset(irsb,i-1,store_tmp)
									if rsp_offset != 0 :
										if rsp_offset in self.taint_rsp[function_addr_str]:
											if isinstance(self.taint_rsp[function_addr_str][rsp_offset],list):
												self.taint_rsp[function_addr_str][rsp_offset].append(taint_tmp[data_tmp])
											else:
												prev_rsp = self.taint_rsp[function_addr_str][rsp_offset]
												self.taint_rsp[function_addr_str][rsp_offset] = []
												self.taint_rsp[function_addr_str][rsp_offset].append(prev_rsp)
												self.taint_rsp[function_addr_str][rsp_offset].append(taint_tmp[data_tmp])
										else:
											self.taint_rsp[function_addr_str][rsp_offset] = taint_tmp[data_tmp]
							elif store_tmp in taint_tmp:
								# MpEngine.dll bug:同一位置上vbtable前后offset不一致，派生类虚基类offset=0x40,基类虚基类offset=0x30
								# 派生类和基类会有mov [rbx+0x30],rdi，会将之前的vftable表清掉，虽不影响程序运行结果，但是影响覆写分析
								MpEngine_bug_addr_list = [0x75a7902a8,0x75A790218,0x75A2A0180]
								if int(function_addr_str,16) in MpEngine_bug_addr_list:
									pass
								else:
									# 后向切片寻找data_tmp的值
									value = self.find_tmp_value(function_addr_str,block.addr,i-1,data_tmp)
									if value != None:
										# 忽略带vbase信息的元组
										if (not isinstance(taint_tmp[store_tmp],int)) and (not isinstance(taint_tmp[store_tmp],long)):
											del taint_tmp[store_tmp]
										else:
											offset_str = hex(taint_tmp[store_tmp]).strip("L")
											
											if offset_str in self.ctor_list[ctor]["this_offset"]:
												self.ctor_list[ctor]["this_offset"][offset_str]["value"]= value
												# TODO:加下面这句会报错
												# self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "var"
											else:
												self.ctor_list[ctor]["this_offset"][offset_str] = dict()
												self.ctor_list[ctor]["this_offset"][offset_str]["value"]= value
												self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "var"
				'''
				if block_addr == 0x14000198c:
					self.flag = 1
				'''
				'''
				if (function_addr_str == "0x140001910"): #0x24e770
					msg = "[*]debug"
					self.debug(irsb=irsb,stmt=stmt,ctor=ctor,taint_tmp=taint_tmp,msg=msg)
				'''
				'''
				if (self.flag == 1) and (function_addr_str == "0x1400020b0"):
					msg = "[*]debug"
					self.debug(irsb=irsb,stmt=stmt,ctor=ctor,taint_tmp=taint_tmp,msg=msg)
				'''
			
			'''
			if block_addr == 0x75A33B314:#0x75a9255a2: #0x75A81C19C:#
				msg = "[*]debug"
				self.debug(irsb,stmt,ctor,taint_tmp,msg)
			'''
			
			if irsb.jumpkind == "Ijk_Ret":
				return
			elif irsb.jumpkind == "Ijk_Call":
				# TODO:不知道为什么前面没有处理
				# libmysqld.dll
				# 0x1802E42E5
				if block_addr not in self.cfg.functions[function_addr_str].nodes:
					start_points = []
					start_points.append(int(function_addr_str,16))
					# 单独处理那一个函数，改为从malloc下一个block开始生成cfg
					mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1,is_one=True,target_block_addr=block_addr)
					for function in mycfg.functions:
						self.cfg.functions[function] = mycfg.functions[function]
				# 忽略syscall 和 间接函数调用  call eax call [eax]
				if ("syscall" not in self.cfg.functions[function_addr_str].nodes[block_addr]) and (not isinstance(irsb.next,pyvex.expr.RdTmp)):
					if double_vbtable == False:
						this_hierarchy = this_hierarchy + 1
						b_addr = irsb.next.con.value

						# 处理GCC下通过plt表的调用
						if self.proj.loader.find_section_containing(b_addr).name == ".plt":
							jmp_block = self.proj.factory.block(b_addr)
							jmp_irsb = jmp_block.vex
							stmt = jmp_irsb.statements[1]
							if isinstance(stmt,pyvex.stmt.WrTmp):
								expr = stmt.data
								if isinstance(expr,pyvex.expr.Load):
									child_expressions = expr.child_expressions
									if isinstance(child_expressions[0],pyvex.expr.Const):
										addr = child_expressions[0].con.value
										state = self.proj.factory.blank_state()
										bv = state.mem[addr].uint64_t.resolved
										b_addr = bv.args[0]

						if b_addr <= (self.proj.loader.main_bin.mapped_base + self.proj.loader.main_bin.max_addr):
							func_addr_str = hex(b_addr).strip("L")
							self.taint_rsp[func_addr_str] = {}
							# TODO: this指针是否要换
							self.overwrite_analysis(ctor,func_addr_str,b_addr,this,this_hierarchy)

				# TODO:不知道为什么block_addr没了，可能前面哪里把它弄没了
				if block_addr not in self.cfg.functions[function_addr_str].nodes:
					start_points = []
					start_points.append(int(function_addr_str,16))
					# 单独处理那一个函数，改为从malloc下一个block开始生成cfg
					mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1,is_one=True,target_block_addr=block_addr)
					for function in mycfg.functions:
						self.cfg.functions[function] = mycfg.functions[function]
					
				successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
				# call throw后面没有指令了
				if len(successors) == 0:
					return
				block_addr = successors[0]
				
				continue
			else:
				# 若存在没有cfg的情况，即前面有间接跳转，如jmp rcx等
				if block_addr not in self.cfg.functions[function_addr_str].nodes:
					start_points = []
					start_points.append(int(function_addr_str,16))
					# 单独处理那一个函数，改为从malloc下一个block开始生成cfg
					mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1,is_one=True,target_block_addr=block_addr)
					for function in mycfg.functions:
						self.cfg.functions[function] = mycfg.functions[function]

				successors = list(self.cfg.functions[function_addr_str].successors(block_addr))

				if len(successors) == 0:
					break
				elif len(successors) == 1:
					block_addr = successors[0]
					continue
				elif len(successors) == 2:

					# TODO:
					# crypto++.dll有一处特例需要这个，否则会进入死循环
					# 这里不知道为啥irsb.statements[-1].dst.value = 0x42960086，而走0x42960020会进入死循环
					# 0x42960081:	sub	rbp, rbx
					# 0x42960084:	jne	0x42960020
					# loop
					# successors:
					# 0x42960020L
					# 0x42960086L
					# predecessors:
					# 0x4296006bL
					# 0x42960074L
					'''
					if (function_addr_str == "0x4295ff60") and (block_addr == 0x42960081):
						block_addr = successors[1]
						continue
					'''
					# 检测循环，选择非循环的分支
					
					'''
					if "loop" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						block_addr = successors[1]
						continue
					'''
					# 选择不是noreturn的那条分支
					if "noreturn" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						if successors[0] == self.cfg.functions[function_addr_str].nodes[block_addr]["noreturn"]:
							block_addr = successors[1]
							continue
						else:
							block_addr = successors[0]
							continue
					# TODO:分支该如何污点分析    vftable都是必经点，所以寻找有vftable的分支？  目前都选择false分支
					else:
						# TODO:错误的2个分支，第一个没有
						# 0x75a31c8fa:	mov	r12d, dword ptr [rbp - 0x45]
						# 0x75a31c8fe:	mov	r9, qword ptr [rip + 0xb08e3b]
						# successors:
						# 0x75a31c90aL
						# 0x75a31c905L
						try:
							a=irsb.statements[-1].dst.value
						except:
							block_addr = successors[1]
							continue
						if successors[0] == irsb.statements[-1].dst.value:
							# 若遇到这种循环，则选择走另一条分支
							# —————————————————   ←——————
							# |              |          |
							# |              |          |
							# |              |          |
							# |              |          |
							# —————————————————         |
							#      ↓      ↓             |
							# —————————  —————————      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# —————————  ———————————jmp—— 
							if loop_flag == 1:
								block_addr = successors[0]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[1]
								continue
						else:
							if loop_flag == 1:
								block_addr = successors[1]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[0]
								continue
				# TODO:不知道为什么产生了3个分支,第一个不是
				# MpEngine.dll
				# 0x75a150fdc:	mov	rax, qword ptr [r14 + 0x10]
				# 0x75a150fe0:	cmp	r9w, word ptr [rax + 0x18]
				# 0x75a150fe5:	jne	0x75a15101b
				# successors:
				# 0x75a4d70a2L
				# 0x75a15101bL
				# 0x75a150fe7L
				elif len(successors) == 3:
					'''
					# 检测循环，选择非循环的分支 
					if "loop" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						block_addr = successors[2]
						continue
					'''
					# 选择不是noreturn的那条分支
					if "noreturn" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						if successors[1] == self.cfg.functions[function_addr_str].nodes[block_addr]["noreturn"]:
							block_addr = successors[2]
							continue
						else:
							block_addr = successors[3]
							continue
					# TODO:分支该如何污点分析    vftable都是必经点，所以寻找有vftable的分支？  目前都选择false分支
					else:
						if successors[1] == irsb.statements[-1].dst.value:
							# 若遇到这种循环，则选择走另一条分支
							# —————————————————   ←——————
							# |              |          |
							# |              |          |
							# |              |          |
							# |              |          |
							# —————————————————         |
							#      ↓      ↓             |
							# —————————  —————————      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# —————————  ———————————jmp—— 
							if loop_flag == 1:
								block_addr = successors[1]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[2]
								continue
						else:
							if loop_flag == 1:
								block_addr = successors[2]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[1]
								continue

	'''
	保存reg值时寻找rsp_offset

	参数：
		irsb：基本块
		i：当前指令索引
		tmp： 当前指令临时变量

	返回：
		rsp_offset：栈内偏移量	
	'''							
	'''
	Look for rsp_offset when saving reg value

	Args:
		irsb: basic block
		i: current instruction index
		tmp: current command temporary variable

	Return:
		rsp_offset: offset within the stack
	''' 
	def find_rsp_offset(self,irsb,i,tmp):
		rsp_offset = 0
		#   ------ IMark(0x14000196a, 5, 0) ------
		#   44 | t41 = Add64(t11,0x0000000000000078)
		#   45 | t43 = GET:I64(rbx)              ←————
		#   46 | STle(t41) = t43
		if isinstance(irsb.statements[i],pyvex.stmt.WrTmp) and isinstance(irsb.statements[i].data,pyvex.expr.Get):
			stmt = irsb.statements[i-1]
			if isinstance(stmt,pyvex.stmt.WrTmp) and tmp == stmt.tmp:
				expr = stmt.data
				if isinstance(expr,pyvex.expr.Binop): 
					if expr.op == "Iop_Add64":
						child_expressions = expr.child_expressions
						if isinstance(child_expressions[1],pyvex.expr.Const):
							rsp_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
							return rsp_offset
						# ELFTODO:取消下面的不知道有影响不
						'''
						if isinstance(child_expressions[1],pyvex.expr.Const):
							rsp_tmp = expr.child_expressions[0].tmp
							j = i - 2
							rsp_flag = 0
							rsp_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
							# 以下循环为了寻找真正的rsp_offset
							# mov     rax, rsp
							# mov     [rax+8], rcx
							# push    r15
							# sub     rsp, 40h
							# mov     qword ptr [rax-18h], 0FFFFFFFFFFFFFFFEh
							# mov     [rax+10h], rbx            rax为之前的rsp，需要寻找现在的rsp偏移
							# mov     [rax+18h], rsi
							# mov     [rax+20h], rdi
							# mov     rbx, rcx
							while j >= 0:
								stmt = irsb.statements[j]

								if isinstance(stmt,pyvex.stmt.Put) and (stmt.offset == 48):
									if (rsp_flag == 0) and (rsp_tmp != stmt.data.tmp):
										rsp_flag = 1
										rsp_tmp = stmt.data.tmp
										stmt = irsb.statements[j-1]
										if isinstance(stmt,pyvex.stmt.WrTmp) and rsp_tmp == stmt.tmp:
											expr = stmt.data
											if isinstance(expr,pyvex.expr.Binop): 
												if expr.op == "Iop_Sub64":
													child_expressions = expr.child_expressions
													if isinstance(child_expressions[1],pyvex.expr.Const):
														rsp_offset -= struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
														rsp_tmp = child_expressions[0].tmp
									# 若后向切片寻找的第一个rsp的tmp等于之前的，则不需要寻找真正的rsp offset
									elif (rsp_flag == 0) and (rsp_tmp == stmt.data.tmp):
										break
									elif (rsp_flag == 1) and (rsp_tmp == stmt.data.tmp):
										stmt = irsb.statements[j-1]
										if isinstance(stmt,pyvex.stmt.WrTmp) and rsp_tmp == stmt.tmp:
											expr = stmt.data
											if isinstance(expr,pyvex.expr.Binop): 
												if expr.op == "Iop_Sub64":
													child_expressions = expr.child_expressions
													rsp_offset -= struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
													rsp_tmp = child_expressions[0].tmp


								j = j - 1                           
							return rsp_offset
						'''
		#   12 | ------ IMark(0x140001956, 1, 0) ------
		#   13 | t3 = GET:I64(rdi)
		#   14 | t31 = Sub64(t29,0x0000000000000008)
		#   15 | PUT(rsp) = t31                        ←————
		#   16 | STle(t31) = t3
		#   17 | PUT(pc) = 0x0000000140001957
		elif isinstance(irsb.statements[i],pyvex.stmt.Put) and (irsb.statements[i].offset == 48):
			stmt = irsb.statements[i-1]

			if isinstance(stmt,pyvex.stmt.WrTmp) and tmp == stmt.tmp:
				expr = stmt.data
				if isinstance(expr,pyvex.expr.Binop): 
					if expr.op == "Iop_Sub64":
						child_expressions = expr.child_expressions
						if isinstance(child_expressions[1],pyvex.expr.Const):
							rsp_offset += struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]

							j = i-2
							# 后向切片寻找rsp操作，然后累加offset
							while j >= 0:
								stmt = irsb.statements[j]
								if isinstance(stmt,pyvex.stmt.Put) and (stmt.offset == 48):
									if isinstance(irsb.statements[j-1],pyvex.stmt.WrTmp):
										expr = irsb.statements[j-1].data
										if isinstance(expr,pyvex.expr.Binop): 
											if expr.op == "Iop_Sub64":
												child_expressions = expr.child_expressions
												if isinstance(child_expressions[1],pyvex.expr.Const):
													rsp_offset += struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
								j = j - 1
							
							return rsp_offset

		'''
		j = i
		rsp_offset = 0
		while j >= 0:
			stmt = irsb.statements[j]
			if isinstance(stmt,pyvex.stmt.WrTmp):
				if tmp == stmt.tmp:
					expr = stmt.data
					if isinstance(expr,pyvex.expr.Binop):
						if expr.op == "Iop_Add64":
							child_expressions = expr.child_expressions
							if isinstance(child_expressions[1],pyvex.expr.Const):
								rsp_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
								return rsp_offset
							else:
								irsb.pp()
								print "[*]error:find_rsp_offset,stmt=%s" % stmt.pp()
								sys.exit()
					else:
						irsb.pp()
						print "[*]error:find_rsp_offset,stmt=%s" % stmt.pp()
						sys.exit()                      
			j = j - 1
		'''
		return rsp_offset   

	'''
	恢复reg值时寻找rsp_offset   
	
	参数：
		function_addr_str：函数地址
		irsb：基本块
		i：当前指令索引
		tmp：当前指令临时变量

	返回：
		rsp_offset：栈内偏移量
	'''
	'''
	Find rsp_offset when restoring reg value

	Args:
		function_addr_str: function address
		irsb: basic block
		i: current instruction index
		tmp: temporary variable of the current instruction

	Return:
		rsp_offset: offset within the stack
	'''
	def is_rsp(self,function_addr_str,irsb,i,tmp):
		rsp_offset = None
		

		stmt = irsb.statements[i-1]
		#  ------ IMark(0x140001b0e, 5, 0) ------
		#   06 | t19 = GET:I64(rsp)
		#   07 | t18 = Add64(t19,0x0000000000000078)
		#   08 | t20 = LDle:I64(t18)
		#   09 | PUT(rbx) = t20     ←————
		if isinstance(stmt,pyvex.stmt.WrTmp) and (tmp == stmt.tmp) and isinstance(stmt.data,pyvex.expr.Load):
			stmt = irsb.statements[i-2]
			if isinstance(stmt,pyvex.stmt.WrTmp) and isinstance(stmt.data,pyvex.expr.Binop):
				expr = stmt.data
				if expr.op == "Iop_Add64":
					if isinstance(expr.child_expressions[1],pyvex.expr.Const):
						rsp_offset = struct.unpack('q',struct.pack('Q',expr.child_expressions[1].con.value))[0]
						return rsp_offset
		#  ------ IMark(0x140001b1d, 1, 0) ------
		#   36 | t10 = LDle:I64(t23)
		#   37 | t24 = Add64(t23,0x0000000000000008)
		#   38 | PUT(rsp) = t24       
		#   39 | PUT(rdi) = t10      ←————
		#   40 | PUT(pc) = 0x0000000140001b1e
		#   41 | ------ IMark(0x140001b1e, 1, 0) ------
		#   42 | t12 = LDle:I64(t24)
		#   43 | t25 = Add64(t24,0x0000000000000008)
		#   44 | PUT(rsp) = t25
		#   45 | PUT(rsi) = t12
		#   46 | PUT(pc) = 0x0000000140001b1f
		elif isinstance(stmt,pyvex.stmt.Put) and (stmt.offset == 48):
			stmt = irsb.statements[i-3]
			if isinstance(stmt,pyvex.stmt.WrTmp) and (tmp == stmt.tmp) and isinstance(stmt.data,pyvex.expr.Load):
				j = i + 1
				rsp_offset = 0
				while j < len(irsb.statements):
					stmt = irsb.statements[j]
					if isinstance(stmt,pyvex.stmt.Put) and (stmt.offset == 48):
						if isinstance(irsb.statements[j-1],pyvex.stmt.WrTmp) and isinstance(irsb.statements[j-1].data,pyvex.expr.Binop):
							expr = irsb.statements[j-1].data
							if expr.op == "Iop_Add64":
								if isinstance(expr.child_expressions[1],pyvex.expr.Const):
									rsp_offset += struct.unpack('q',struct.pack('Q',expr.child_expressions[1].con.value))[0]
					j = j + 1
				# 去掉ret的pop
				rsp_offset -= 8
				return rsp_offset

		# 02 | ------ IMark(0x14000132d, 5, 0) ------
   		# 03 | t7 = GET:I64(rsp)
  		# 04 | t6 = Add64(t7,0x0000000000000040)
   		# 05 | t8 = LDle:I64(t6)                         ←————
   		# 06 | ------ IMark(0x140001332, 4, 0) ------
   		# 07 | t1 = Add64(t8,0x0000000000000010)
   		# 08 | PUT(cc_op) = 0x0000000000000004
   		# 09 | PUT(cc_dep1) = t8
   		# 10 | PUT(cc_dep2) = 0x0000000000000010
  		# 11 | PUT(rax) = t1
  		# 12 | ------ IMark(0x140001336, 3, 0) ------
   		# 13 | PUT(rcx) = t1
   		stmt = irsb.statements[i]
   		if isinstance(stmt,pyvex.stmt.WrTmp) and isinstance(stmt.data,pyvex.expr.Load):
   			stmt = irsb.statements[i-1]
			if isinstance(stmt,pyvex.stmt.WrTmp) and isinstance(stmt.data,pyvex.expr.Binop):
				expr = stmt.data
				if expr.op == "Iop_Add64":
					child_expressions = expr.child_expressions
					if isinstance(child_expressions[1],pyvex.expr.Const):
						rsp_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
						return rsp_offset
					'''
					if isinstance(expr.child_expressions[1],pyvex.expr.Const):
						rsp_tmp = expr.child_expressions[0].tmp
						j = i - 2
						rsp_flag = 0
						rsp_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
						# 以下循环为了寻找真正的rsp_offset
						# mov     rax, rsp
						# mov     [rax+8], rcx
						# push    r15
						# sub     rsp, 40h
						# mov     qword ptr [rax-18h], 0FFFFFFFFFFFFFFFEh
						# mov     [rax+10h], rbx            rax为之前的rsp，需要寻找现在的rsp偏移
						# mov     [rax+18h], rsi
						# mov     [rax+20h], rdi
						# mov     rbx, rcx
						while j >= 0:
							stmt = irsb.statements[j]

							if isinstance(stmt,pyvex.stmt.Put) and (stmt.offset == 48):
								if (rsp_flag == 0) and (rsp_tmp != stmt.data.tmp):
									rsp_flag = 1
									rsp_tmp = stmt.data.tmp
									stmt = irsb.statements[j-1]
									if isinstance(stmt,pyvex.stmt.WrTmp) and rsp_tmp == stmt.tmp:
										expr = stmt.data
										if isinstance(expr,pyvex.expr.Binop): 
											if expr.op == "Iop_Sub64":
												child_expressions = expr.child_expressions
												if isinstance(child_expressions[1],pyvex.expr.Const):
													rsp_offset -= struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
													rsp_tmp = child_expressions[0].tmp
								# 若后向切片寻找的第一个rsp的tmp等于之前的，则不需要寻找真正的rsp offset
								elif (rsp_flag == 0) and (rsp_tmp == stmt.data.tmp):
									break
								elif (rsp_flag == 1) and (rsp_tmp == stmt.data.tmp):
									stmt = irsb.statements[j-1]
									if isinstance(stmt,pyvex.stmt.WrTmp) and rsp_tmp == stmt.tmp:
										expr = stmt.data
										if isinstance(expr,pyvex.expr.Binop): 
											if expr.op == "Iop_Sub64":
												child_expressions = expr.child_expressions
												rsp_offset -= struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
												rsp_tmp = child_expressions[0].tmp


							j = j - 1                           
						return rsp_offset
					'''
		'''
		rsp_offset = 0
		j = i
		load_flag = 0
		add_flag = 0
		while j >= 0:
			stmt = irsb.statements[j]
			if isinstance(stmt,pyvex.stmt.WrTmp):
				if tmp == stmt.tmp:             
					expr = stmt.data
					if isinstance(expr,pyvex.expr.Load):
						if isinstance(expr.child_expressions[0],pyvex.expr.RdTmp):
							load_flag = 1
							tmp = expr.child_expressions[0].tmp
					elif isinstance(expr,pyvex.expr.Binop):
						if (load_flag == 1) and (expr.op == "Iop_Add64"):
							if isinstance(expr.child_expressions[1],pyvex.expr.Const):
								add_flag = 1
								tmp = expr.child_expressions[0].tmp
								rsp_offset = expr.struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
							else:
								rsp_offset = 0
								return rsp_offset
					elif isinstance(expr,pyvex.expr.Get):
						# rsp = offset 48
						if (expr.offset == 48) and (load_flag == 1) and (add_flag == 1):
							irsb.pp()
							stmt.pp()
							return rsp_offset
						else:
							rsp_offset = 0
			j = j - 1
		'''
		return rsp_offset

	'''
	调试模式

	可根据实际情况逐指令，基本块，函数分析，输入exit退出调试模式并结束程序

	参数：
		irsb：基本块
		stmt：当前指令
		ctor：正在分析的对象内存布局索引
		taint_tmp：当前污点临时变量
		msg：备注信息
	'''
	'''
	Debug mode

	According to the actual situation, one by one instruction, basic block, function analysis, enter exit to exit the debugging mode and end the program

	Args:
		irsb: basic block
		stmt: current instruction
		ctor: the index of object memory layout being analyzed
		taint_tmp: current stain temporary variable
		msg: Remark information
	'''
	def debug(self,irsb=None,stmt=None,ctor=None,taint_tmp=None,msg=None):
		if msg != None:
			print msg
		if irsb != None:
			irsb.pp()
		if stmt != None:
			stmt.pp()
		print "taint_register:"
		print self.taint_register
		print "taint_rsp:"
		print self.taint_rsp
		if taint_tmp != None:
			print "taint_tmp:"
			print taint_tmp
		if ctor != None:
			print "ctor:" + ctor
			print self.ctor_list[ctor]
		cmd = raw_input("cmd:")
		if cmd == "exit":
			sys.exit()

	'''
	后向切片寻找data_tmp的值

	参数：
		function_addr_str：函数地址
		block_addr：基本块地址
		i：当前指令索引
		tmp：要寻找的临时变量

	返回：
		value：要寻找的临时变量的值
	'''
	'''
	Backward slice to find the value of data_tmp

	Args:
		function_addr_str: function address
		block_addr: basic block address
		i: current instruction index
		tmp: temporary variable to look for

	Return:
		value: the value of the temporary variable to look for
	'''
	def find_tmp_value(self,function_addr_str,block_addr,i,tmp):
		value = None        
		block = self.proj.factory.block(block_addr)
		irsb = block.vex
		j = i
		reg = None
		while j >= 0:
			stmt = irsb.statements[j]
			if isinstance(stmt,pyvex.stmt.WrTmp) and (tmp == stmt.tmp):
				expr = stmt.data
				if isinstance(expr,pyvex.expr.Get):
					reg = expr.offset
			if (reg != None) and isinstance(stmt,pyvex.stmt.Put) and (reg == stmt.offset):
				# 只考虑常量，忽略tmp -> [rax+0x30]
				if isinstance(stmt.data,pyvex.expr.Const):
					value = stmt.data.con.value
					return value
			j = j - 1
		traced_block = {}
		# 函数内后向切片寻找
		if (value == None) and (reg != None):
			# 若函数不存在，生成CFG
			if function_addr_str not in self.cfg.functions:
				start_points = []
				start_points.append(int(function_addr_str,16))
				# 单独处理那一个函数，改为从malloc下一个block开始生成cfg
				mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1,is_one=True,target_block_addr=block_addr)
				for function in mycfg.functions:
					self.cfg.functions[function] = mycfg.functions[function]

			# TODO:block_addr可能不存在，可能是CFG生成阶段实现有问题导致基本块的缺失
			try:
				predecessors = list(self.cfg.functions[function_addr_str].predecessors(block_addr))
				for predecessor in predecessors:
					traced_block[predecessor] = 1
					value = self.find_tmp_value_backward(function_addr_str,predecessor,reg,traced_block)
					if value != None:
						return value
			except:
				return value
		return value
	'''
	递归后向切片寻找data_tmp的值 
	
	参数：
		function_addr_str：函数地址
		block_addr：基本块地址
		reg：追踪的寄存器
		traced_block：分析过的基本块

	返回：
		value：要寻找的临时变量的值	
	'''
	'''
	Find the value of data_tmp in the slice after recursion

	Args:
		function_addr_str: function address
		block_addr: basic block address
		reg: tracked register
		traced_block: analyzed basic block

	Return:
		value: the value of the temporary variable to be found
	'''
	def find_tmp_value_backward(self,function_addr_str,block_addr,reg,traced_block):
		value = None
		# 检测循环
		if block_addr in traced_block:
			if traced_block[block_addr] > 10:
				return value
			else:
				traced_block[block_addr] += 1
		else:
			traced_block[block_addr] = 1
		#print function_addr_str+" block:"+hex(block_addr)		
		block = self.cfg.functions[function_addr_str].nodes[block_addr]["block"]
		irsb = block.vex
		

		for stmt in irsb.statements[::-1]:
			if isinstance(stmt,pyvex.stmt.Put) and (reg == stmt.offset):
				# TODO:目前只找data为常量的，为其他tmp(reg)传递的忽略，一般为普通变量，与vftable无关
				if isinstance(stmt.data,pyvex.expr.Const):
					value = stmt.data.con.value
					return value


		predecessors = list(self.cfg.functions[function_addr_str].predecessors(block_addr))
		for predecessor in predecessors:
			value = self.find_tmp_value_backward(function_addr_str,predecessor,reg,traced_block)
			if value != None:
				return value
		return value

	'''
	寻找和vftable相关的内存布局变量

	参数：
		ctor：构造函数
		new_next_addr：new()的下一个基本块地址
		new_func_addr_str：new()地址
	'''
	'''
	Find memory layout variables related to vftable

	Args:
		ctor: constructor
		new_next_addr: next basic block address of new()
		new_func_addr_str: new() address
	'''
	def handle_new_next_block(self,ctor,new_next_addr,new_func_addr_str):
		new_next_block = self.proj.factory.block(new_next_addr)
		new_next_irsb = new_next_block.vex
		taint_register = {}
		taint_register[16] = 0
		taint_tmp = {}
		# 只考虑rax offset = 16 , [rax+8],rbx
		for i,stmt in enumerate(new_next_irsb.statements):
			if isinstance(stmt,pyvex.stmt.WrTmp):
				expr = stmt.data
				if isinstance(expr,pyvex.expr.Get):
					# 污点传播
					if expr.offset in taint_register:
						taint_tmp[stmt.tmp] = taint_register[expr.offset]
					else:
						# 污点消除
						if stmt.tmp in taint_tmp:
							del taint_tmp[stmt.tmp]

				elif isinstance(expr,pyvex.expr.Binop):
					# tmp+const
					if expr.op == "Iop_Add64":
						child_expressions = expr.child_expressions
						if isinstance(child_expressions[0],pyvex.expr.RdTmp):
							tmp = child_expressions[0].tmp
							if isinstance(child_expressions[1],pyvex.expr.RdTmp):
								tmp2 = child_expressions[1].tmp
								# 污点传播
								if (tmp in taint_tmp) and (tmp2 in taint_tmp):
									taint_tmp[stmt.tmp] = taint_tmp[tmp] + taint_tmp[tmp2]
								else:
									# 污点消除
									if stmt.tmp in taint_tmp:
										del taint_tmp[stmt.tmp]
							else:
								const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
								# 污点传播
								if tmp in taint_tmp:
									taint_tmp[stmt.tmp] = taint_tmp[tmp] + const
								else:
									# 污点消除
									if stmt.tmp in taint_tmp:
										del taint_tmp[stmt.tmp]
						else:
							# 污点消除
							if stmt.tmp in taint_tmp:
								del taint_tmp[stmt.tmp]

			elif isinstance(stmt,pyvex.stmt.Store):
				expr = stmt.data 
				if isinstance(expr,pyvex.expr.RdTmp):
					data_tmp = expr.tmp
					if data_tmp not in taint_tmp:
						store_tmp = stmt.addr.tmp
						if store_tmp in taint_tmp:
							# 后向切片寻找data_tmp的值
							value = self.find_tmp_value(new_func_addr_str,new_next_block.addr,i-1,data_tmp)
							if value != None:
								offset_str = hex(taint_tmp[store_tmp]).strip("L")
								# 将搜索的到结果标记污点
								taint_tmp[data_tmp] = value

								if offset_str in self.ctor_list[ctor]["this_offset"]:
									self.ctor_list[ctor]["this_offset"][offset_str]["value"]= value
								else:
									self.ctor_list[ctor]["this_offset"][offset_str] = dict()
									self.ctor_list[ctor]["this_offset"][offset_str]["value"]= value
									self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "var"
					else:
						# 忽略const
						if isinstance(stmt.addr,pyvex.expr.RdTmp):
							store_tmp = stmt.addr.tmp
							if store_tmp in taint_tmp:
								offset_str = hex(taint_tmp[store_tmp]).strip("L")
								if offset_str in self.ctor_list[ctor]["this_offset"]:
									self.ctor_list[ctor]["this_offset"][offset_str]["value"]= taint_tmp[data_tmp]
								else:
									self.ctor_list[ctor]["this_offset"][offset_str] = dict()
									self.ctor_list[ctor]["this_offset"][offset_str]["value"]= taint_tmp[data_tmp]
									self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "var"

	'''
	后向切片查看是否是静态对象，rsp|rbp

	参数：
		function_addr_str：函数地址
		block_addr：基本块地址
		i：当前指令索引
		tmp：当前指令临时变量

	返回：
		is_not_new：是否是静态对象，若是则为True，否则为False
	'''
	'''
	Backward slice to see if it is a static object, rsp|rbp

	Args:
		function_addr_str: function address
		block_addr: basic block address
		i: current instruction index
		tmp: temporary variable of the current instruction

	Return:
		is_not_new: whether it is a static object, True if it is, otherwise False
	'''
	def is_not_new_opreation(self,function_addr_str,block_addr,i,tmp):
		is_not_new = False        
		block = self.proj.factory.block(block_addr)
		irsb = block.vex
		j = i
		while j >= 0:
			stmt = irsb.statements[j]
			if isinstance(stmt,pyvex.stmt.WrTmp) and (tmp == stmt.tmp):
				expr = stmt.data
				if isinstance(expr,pyvex.expr.Binop):
					if expr.op == "Iop_Sub64":
						child_expressions = expr.child_expressions
						if isinstance(child_expressions[0],pyvex.expr.RdTmp):
							tmp = child_expressions[0].tmp
					elif expr.op == "Iop_Add64":
						child_expressions = expr.child_expressions
						if isinstance(child_expressions[0],pyvex.expr.RdTmp):
							tmp = child_expressions[0].tmp
				elif isinstance(expr,pyvex.expr.Get):
					# rsp|rbp
					if (expr.offset == 48) or (expr.offset == 56):
						is_not_new = True
						return is_not_new
					else:
						is_not_new = False
						return is_not_new
			j = j - 1
		traced_block = {}
		# 若存在没有cfg的情况，即前面有间接跳转，如jmp rcx等
		if block_addr not in self.cfg.functions[function_addr_str].nodes:
			start_points = []
			start_points.append(int(function_addr_str,16))
			# 单独处理那一个函数，改为从malloc下一个block开始生成cfg
			mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1,is_one=True,target_block_addr=block_addr)
			for function in mycfg.functions:
				self.cfg.functions[function] = mycfg.functions[function]
		# 函数内后向切片寻找
		predecessors = list(self.cfg.functions[function_addr_str].predecessors(block_addr))
		for predecessor in predecessors:
			traced_block[predecessor] = 1
			is_not_new = self.is_not_new_opreation_backward(function_addr_str,predecessor,tmp,traced_block)
			if is_not_new == True:
				return is_not_new
		return is_not_new

	'''
	递归后向切片查看是否是非new操作的类，rsp|rbp

	参数：
		function_addr_str：函数地址
		block_addr：基本块地址
		tmp：追踪的临时变量
		traced_block：已分析的基本块

	返回：
		is_not_new：是否是静态对象，若是则为True，否则为False
	'''
	'''
	Recursively slice backward to see if it is a non-new operation class, rsp|rbp

	Args:
		function_addr_str: function address
		block_addr: basic block address
		tmp: temporary variables tracked
		traced_block: analyzed basic block

	Return:
		is_not_new: whether it is a static object, True if it is, otherwise False
	'''
	def is_not_new_opreation_backward(self,function_addr_str,block_addr,tmp,traced_block):
		is_not_new = False 
		# 检测循环
		if block_addr in traced_block:
			if traced_block[block_addr] > 10:
				return is_not_new
			else:
				traced_block[block_addr] += 1
		else:
			traced_block[block_addr] = 1
		block = self.cfg.functions[function_addr_str].nodes[block_addr]["block"]
		irsb = block.vex
		
		for stmt in irsb.statements[::-1]:
			if isinstance(stmt,pyvex.stmt.WrTmp) and (tmp == stmt.tmp):
				expr = stmt.data
				if isinstance(expr,pyvex.expr.Binop):
					if expr.op == "Iop_Sub64":
						child_expressions = expr.child_expressions
						if isinstance(child_expressions[0],pyvex.expr.RdTmp):
							tmp = child_expressions[0].tmp
					elif expr.op == "Iop_Add64":
						child_expressions = expr.child_expressions
						if isinstance(child_expressions[0],pyvex.expr.RdTmp):
							tmp = child_expressions[0].tmp
				elif isinstance(expr,pyvex.expr.Get):
					# rsp|rbp
					if (expr.offset == 48) or (expr.offset == 56):
						is_not_new = True
						return is_not_new
					else:
						is_not_new = False
						return is_not_new

		# 函数内后向切片寻找
		predecessors = list(self.cfg.functions[function_addr_str].predecessors(block_addr))
		for predecessor in predecessors:
			is_not_new = self.is_not_new_opreation_backward(function_addr_str,predecessor,tmp,traced_block)
			if is_not_new == True:
				return is_not_new

		return is_not_new
	'''	
	检测是否构造函数完全内联,只需要识别offset=0的vftable即可计数

	初始污点为rax

	参数：
		ctor：构造函数
	'''
	'''
	Check if the constructor is completely inline, only need to identify vftable with offset=0 to count

	The initial taint is rax
	
	Args:
		ctor: constructor
	'''
	def is_ctor_multi_class(self,ctor):
		is_multi_class = False

		taint_register = {}
		taint_tmp = {}

		function_addr_str = ctor
		block_addr = int(ctor,16)
		traced_block = dict()

		class_count = 0
		while 1:
			loop_flag = 0
			if block_addr in traced_block:
				#print hex(block_addr)
				loop_flag = 1
				traced_block[block_addr] += 1
				if traced_block[block_addr] >= 10:
					loop_flag = 2
				# 防止无限循环
				if traced_block[block_addr] >= 10000:
					return
			else:
				traced_block[block_addr] = 0

			# 排除只有jmp的系统调用函数
			# jmp cs:__imp__RTDynamicCast
			if function_addr_str not in self.cfg.functions:
				b_addr = int(function_addr_str,16)
				block = self.proj.factory.block(b_addr)
				if (len(block.capstone.insns) == 1) and (block.capstone.insns[-1].insn.insn_name() == "jmp"):
					return

			# 若存在没有cfg的情况，即前面有间接跳转，如jmp rcx等
			if block_addr not in self.cfg.functions[function_addr_str].nodes:
				start_points = []
				start_points.append(int(function_addr_str,16))
				# 单独处理那一个函数，改为从malloc下一个block开始生成cfg
				mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1,is_one=True,target_block_addr=block_addr)
				for function in mycfg.functions:
					self.cfg.functions[function] = mycfg.functions[function]

			block = self.cfg.functions[function_addr_str].nodes[block_addr]["block"]
			irsb = block.vex


			if isinstance(irsb.next,pyvex.expr.Const):
				if (irsb.jumpkind == "Ijk_Call") and (irsb.next.con.value in self.new_list):
					if class_count >= 2:
						is_multi_class = True
						return is_multi_class

					taint_register = {}
					taint_register[16] = 0
					taint_tmp = {}


					successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
					# 异常处理函数后面没有指令
					if len(successors) != 0:
						block_addr = successors[0]
						continue
			for i,stmt in enumerate(irsb.statements):
				# reg->tmp
				# tmp->tmp
				if isinstance(stmt,pyvex.stmt.WrTmp):
					expr = stmt.data
					# reg->tmp
					if isinstance(expr,pyvex.expr.Get):
						# 污点传播
						if expr.offset in taint_register:
							taint_tmp[stmt.tmp] = taint_register[expr.offset]
						else:
							# 污点消除
							if stmt.tmp in taint_tmp:
								del taint_tmp[stmt.tmp]

					# tmp->tmp
					elif isinstance(expr,pyvex.expr.Binop):
						# tmp+const
						if expr.op == "Iop_Add64":
							child_expressions = expr.child_expressions
							# 排除以下情况：
							# t3 = Add64(0x0000000000000000,t2) 
							if isinstance(child_expressions[0],pyvex.expr.RdTmp):
								tmp = child_expressions[0].tmp
								if isinstance(child_expressions[1],pyvex.expr.RdTmp):
									tmp2 = child_expressions[1].tmp
									# 污点传播
									if (tmp in taint_tmp) and (tmp2 in taint_tmp):
										taint_tmp[stmt.tmp] = taint_tmp[tmp] + taint_tmp[tmp2]
									else:
										# 污点消除
										if stmt.tmp in taint_tmp:
											del taint_tmp[stmt.tmp]
								else:
									const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
									# 污点传播
									if tmp in taint_tmp:
										taint_tmp[stmt.tmp] = taint_tmp[tmp] + const
									else:
										# 污点消除
										if stmt.tmp in taint_tmp:
											del taint_tmp[stmt.tmp]
						elif expr.op == "Iop_Sub64":
							child_expressions = expr.child_expressions
							# 排除以下情况：
							# t3 = Sub64(0x0000000000000000,t2) -> neg rax  取反
							if isinstance(child_expressions[0],pyvex.expr.RdTmp):
								tmp = child_expressions[0].tmp
								# 污点传播
								if tmp in taint_tmp:
									# 40 | ------ IMark(0x154a, 3, 0) ------
									# 41 | t48 = LDle:I64(t47)
									# 42 | ------ IMark(0x154d, 4, 0) ------
									# 43 | t13 = Sub64(t48,0x0000000000000018)  <-----------
									# 44 | PUT(pc) = 0x0000000000001551
									# eg. vftable-0x18
									if self.filetype == "ELF" and isinstance(irsb.statements[i-2],pyvex.stmt.WrTmp) and isinstance(irsb.statements[i-2].data,pyvex.expr.Load):
										vftable = taint_tmp[tmp]
										for VTT in self.VTT_list:
											if vftable in self.VTT_list[VTT]["vftable"]:
												const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
												vftable_addr = int(vftable,16)
												vbase_offset_addr = vftable_addr - const
												taint_tmp[stmt.tmp] = (vbase_offset_addr,"VTT")
												break
									elif isinstance(child_expressions[1],pyvex.expr.Const):
										const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]                              
										taint_tmp[stmt.tmp] = taint_tmp[tmp] - const
								else:
									# 污点消除
									if stmt.tmp in taint_tmp:
										del taint_tmp[stmt.tmp]
						else:
							# t28 = CmpEQ8(t30,t29)
							if stmt.tmp in taint_tmp:
								del taint_tmp[stmt.tmp]
				# const->reg
				# tmp->reg
				elif isinstance(stmt,pyvex.stmt.Put):
					expr = stmt.data
					# tmp->reg
					if isinstance(expr,pyvex.expr.RdTmp):
						tmp = expr.tmp
						# 污点传播
						if tmp in taint_tmp:
							taint_register[stmt.offset] = taint_tmp[tmp]
						else:
							# 污点消除
							if stmt.offset in taint_register:
								del taint_register[stmt.offset]
					# const->reg
					elif isinstance(expr,pyvex.expr.Const):
						# 检查VTT赋值
						if self.filetype == "ELF" :
							find = 0
							const = expr.con.value
							const_str = hex(const).strip("L")
							for VTT in self.VTT_list:
								if const_str in self.VTT_list[VTT]["addr"]:
									self.taint_register[stmt.offset] = const_str
									find = 1
									break
							if find == 0:
								# 污点消除
								if stmt.offset in self.taint_register:
									del self.taint_register[stmt.offset]
						# 污点消除
						elif stmt.offset in self.taint_register:
							del self.taint_register[stmt.offset]

				# vftable_addr->mem[tmp]
				elif isinstance(stmt,pyvex.stmt.Store):
					expr = stmt.data
					if isinstance(expr,pyvex.expr.Const):
						const = stmt.data.con.value
						const_str = hex(const).strip("L")
						if const_str in self.vftable_list:
							tmp = stmt.addr.tmp
							if tmp in taint_tmp:
								class_count += 1
								if class_count >= 2:
									is_multi_class = True
									return is_multi_class
								taint_register = {}
								taint_tmp = {}
							# 这里不需要，vftable只检测offset = 0的
							'''
							else:
								msg = "[*]error:ctor vftable leave out"
								print "local taint_register:"
								print taint_register
								self.debug(irsb=irsb,stmt=stmt,ctor=ctor,taint_tmp=taint_tmp,msg=msg)
							'''


					

			if irsb.jumpkind == "Ijk_Ret":
				if class_count >= 2:
					is_multi_class = True
				return is_multi_class
			elif irsb.jumpkind == "Ijk_Call":
				if class_count >= 2:
					is_multi_class = True
					return is_multi_class
				successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
				# 异常处理函数后面没有指令
				if len(successors) == 0:
					return
				block_addr = successors[0]
				continue
			else:
				if class_count >= 2:
					is_multi_class = True
					return is_multi_class
				successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
				if len(successors) == 0:
					if class_count >= 2:
						is_multi_class = True
					return is_multi_class
				elif len(successors) == 1:
					block_addr = successors[0]
					continue
				elif len(successors) == 2:
					'''
					# 检测循环，选择非循环的分支 
					if "loop" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						block_addr = successors[1]
						continue
					'''
					# 选择不是noreturn的那条分支
					if "noreturn" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						if successors[0] == self.cfg.functions[function_addr_str].nodes[block_addr]["noreturn"]:
							block_addr = successors[1]
							continue
						else:
							block_addr = successors[0]
							continue
					# TODO:分支该如何污点分析    vftable都是必经点，所以寻找有vftable的分支？  目前都选择false分支
					else:
						# TODO:错误的2个分支，第一个没有
						# 0x75a31c8fa:	mov	r12d, dword ptr [rbp - 0x45]
						# 0x75a31c8fe:	mov	r9, qword ptr [rip + 0xb08e3b]
						# successors:
						# 0x75a31c90aL
						# 0x75a31c905L
						try:
							a=irsb.statements[-1].dst.value
						except:
							block_addr = successors[1]
							continue
						if successors[0] == irsb.statements[-1].dst.value:
							# 若遇到这种循环，则选择走另一条分支
							# —————————————————   ←——————
							# |              |          |
							# |              |          |
							# |              |          |
							# |              |          |
							# —————————————————         |
							#      ↓      ↓             |
							# —————————  —————————      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# —————————  ———————————jmp—— 
							if loop_flag == 1:
								block_addr = successors[0]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[1]
								continue
						else:
							if loop_flag == 1:
								block_addr = successors[1]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[0]
								continue
				# TODO:不知道为什么产生了3个分支,第一个不是
				# 0x75a150fdc:	mov	rax, qword ptr [r14 + 0x10]
				# 0x75a150fe0:	cmp	r9w, word ptr [rax + 0x18]
				# 0x75a150fe5:	jne	0x75a15101b
				# successors:
				# 0x75a4d70a2L
				# 0x75a15101bL
				# 0x75a150fe7L
				elif len(successors) == 3:
					'''
					# 检测循环，选择非循环的分支 
					if "loop" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						block_addr = successors[2]
						continue
					'''
					# 选择不是noreturn的那条分支
					if "noreturn" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						if successors[1] == self.cfg.functions[function_addr_str].nodes[block_addr]["noreturn"]:
							block_addr = successors[2]
							continue
						else:
							block_addr = successors[3]
							continue
					# TODO:分支该如何污点分析    vftable都是必经点，所以寻找有vftable的分支？  目前都选择false分支
					else:
						if successors[1] == irsb.statements[-1].dst.value:
							# 若遇到这种循环，则选择走另一条分支
							# —————————————————   ←——————
							# |              |          |
							# |              |          |
							# |              |          |
							# |              |          |
							# —————————————————         |
							#      ↓      ↓             |
							# —————————  —————————      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# —————————  ———————————jmp—— 
							if loop_flag == 1:
								block_addr = successors[1]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[2]
								continue
						else:
							if loop_flag == 1:
								block_addr = successors[2]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[1]
								continue



		return is_multi_class

	# 预分析
	def pre_analysis(self):
		self.new_addr_init()

	'''
	记录new操作地址
	'''
	'''
	Record new operation address
	'''
	def new_addr_init(self):
		for ctor in self.ctor_list:
			if "addr" in self.ctor_list[ctor]["new_addr"]:
				new_addr_call = int(self.ctor_list[ctor]["new_addr"]["addr"],16)
				block = self.proj.factory.block(new_addr_call)
				new_addr = block.vex.next.con.value
				if new_addr not in self.new_list:
					self.new_list.append(new_addr)
	'''
	后续分析

	1. 分析拥有多个对象的构造函数
	2. 若vftable不存在对应的构造函数，则进行析构函数分析
	3. 删除里面的异常处理等vftable（不是该ctor的vftbale）
	4. GCC：当派生类只直接继承虚基类，并没有子类，识别出其中的虚基类
	'''
	'''
	Follow-up analysis

	1. Analyze the constructor with multiple objects
	2. If there is no corresponding constructor in vftable, perform destructor analysis
	3. Delete the exception handling etc. vftable (not the ctor's vftbale)
	4. GCC: When the derived class only directly inherits the virtual base class and has no subclasses, the virtual base class is identified
	'''
	def post_analysis(self):
		# 分析拥有多类的构造函数 no_new and multi_class
		i = 1 
		for ctor in self.ctor_list:
			
			# 0 new operation与ctor在同一层
			if (("no_new" in self.ctor_list[ctor]) or ("multi_class" in self.ctor_list[ctor])) and (self.ctor_list[ctor]["new_addr"]["hierarchy"] == 0):
				self.ctor_list[ctor]["this_offset"] = {}

				self.taint_register = {}
				self.taint_rsp = {}
				self.taint_rsp[ctor] = {}
				self.vftable_num = 1
				class_num = 1

				self.multi_ctor_list[ctor+"-"+str(class_num)] = {}
				self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"] = {}
				self.multi_ctor_list[ctor+"-"+str(class_num)]["new_addr"] = self.ctor_list[ctor]["new_addr"] 

				new_addr = int(self.ctor_list[ctor]["new_addr"]["addr"],16)
				block = self.proj.factory.block(new_addr)
				insn = block.capstone.insns[-1]
				block_addr = insn.address + insn.size


				# rax = offset 16
				this = 16
				self.taint_register[this] = 0
				self.ctor_multi_class_analysis(ctor,ctor,block_addr,this,0,class_num)
				print "%s %s static_taint_analysis ctor_multi_class completion" % (i,ctor)
				i += 1

		for ctor in self.multi_ctor_list:
			self.ctor_list[ctor] = self.multi_ctor_list[ctor]

		# 分析没有用到的类，即没有构造函数只有析构函数的vftable
		self.no_ctor_analysis()

		# 删除里面的异常处理等vftable（不是该ctor的vftbale）
		for ctor in self.ctor_list:
			for offset in self.ctor_list[ctor]["this_offset"]:
				if ((self.ctor_list[ctor]["this_offset"][offset]["attribute"] == "vftable") or (self.ctor_list[ctor]["this_offset"][offset]["attribute"] == "vbase")) and isinstance(self.ctor_list[ctor]["this_offset"][offset]["value"],list):
					traced_vftable_list = []
					del_list = []
					for vftable in self.ctor_list[ctor]["this_offset"][offset]["value"]:
						if vftable[0] in traced_vftable_list:
							del_list.append(vftable[0])
						else:
							traced_vftable_list.append(vftable[0])
					if len(del_list) > 0:
						vftable_list = []
						vf_list = []
						for vftable in self.ctor_list[ctor]["this_offset"][offset]["value"]:
							# ELFTODO：有的vftable确实写入了多次，只保留一个，这样可能造成异常处理的类也与其他类建立联系						
							if vftable[0] not in vf_list:
								vftable_list.append(vftable)
								vf_list.append(vftable[0])
							'''
							if vftable[0] not in del_list:
								vftable_list.append(vftable)
							'''
						self.ctor_list[ctor]["this_offset"][offset]["value"] = vftable_list

		# 当派生类只直接继承虚基类，并没有子类时，没有VTT，而且虚基类的vftable写入偏移时立即数，需要查看对象内存布局中偏移为0的最后一个vftable（派生类）的OffsetToVbase字段，将对应偏移标记成vbase
		if self.filetype == "ELF":
			for ctor in self.ctor_list:
				# ELFTO: 有的构造函数完全内联，分析时没有找到对应的vftable路线
				if ("0x0" in self.ctor_list[ctor]["this_offset"]) and (self.ctor_list[ctor]["this_offset"]["0x0"]["attribute"] == "vftable"):
					vftable = self.ctor_list[ctor]["this_offset"]["0x0"]["value"][-1][0]
					if "vbase_offset" in self.vftable_list[vftable]:
						for offset in self.vftable_list[vftable]["vbase_offset"]:
							offset_str = hex(offset).strip("L")
							if offset_str in self.ctor_list[ctor]["this_offset"]:
								self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vbase"

	'''
	构造函数完全内联分析

	每遇到新的new()污点重置

	参数：
		ctor：构造函数
		function_addr_str：函数地址
		block_addr：基本块地址
		this：this指针
		hierarchy：递归次数，代表函数层级
		class_num：对象数量，用来区分不同的对象内存布局
	'''
	'''
	Constructor full inline analysis

	Every time new() stains are reset

	Args:
		ctor: constructor
		function_addr_str: function address
		block_addr: basic block address
		this: this pointer
		hierarchy: Recursion times, representing function hierarchy
		class_num: number of objects, used to distinguish the memory layout of different objects
	'''
	def ctor_multi_class_analysis(self,ctor,function_addr_str,block_addr,this,hierarchy,class_num):
		if hierarchy >=5:
			return
		this_hierarchy = hierarchy
		'''
		# TODO: MpEngine.dll 0x75a1f931c vbtable特例，第一项为0，然后有三项，日后处理
		if function_addr_str == "0x75a1f931c":
			return 
		# TODO: MpEngine.dll bug PEFileWriter与PEFileReader vbtable偏移不一样
		if function_addr_str == "0x75a13a10c":
			return
		# TODO: QuantLib.dll 不知道哪里的问题无限循环了
		if function_addr_str == "0x180207940":
			return
		if function_addr_str == "0x1801d8fb0":
			return
		if function_addr_str == "0x1803e1320":
			return
		if function_addr_str == "0x1802af410":
			return
		if function_addr_str == "0x1805e8a50":
			return
		'''
		traced_block = dict()
		while 1:
			#print function_addr_str,hex(block_addr)
			loop_flag = 0
			if block_addr in traced_block:
				#print hex(block_addr)
				loop_flag = 1
				traced_block[block_addr] += 1
				if traced_block[block_addr] >= 10:
					loop_flag = 2
				# 防止无限循环
				if traced_block[block_addr] >= 10000:
					return
			else:
				traced_block[block_addr] = 0
			
			# 排除只有jmp的系统调用函数
			# jmp cs:__imp__RTDynamicCast
			if function_addr_str not in self.cfg.functions:
				b_addr = int(function_addr_str,16)
				block = self.proj.factory.block(b_addr)
				if (len(block.capstone.insns) == 1) and (block.capstone.insns[-1].insn.insn_name() == "jmp"):
					return

			# 若存在没有cfg的情况，即前面有间接跳转，如jmp rcx等
			if block_addr not in self.cfg.functions[function_addr_str].nodes:
				start_points = []
				start_points.append(int(function_addr_str,16))
				# 单独处理那一个函数，改为从malloc下一个block开始生成cfg
				mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1,is_one=True,target_block_addr=block_addr)
				for function in mycfg.functions:
					self.cfg.functions[function] = mycfg.functions[function]

			block = self.cfg.functions[function_addr_str].nodes[block_addr]["block"]

			irsb = block.vex
			
			taint_tmp = {}
			for i,stmt in enumerate(irsb.statements):
				# reg->tmp
				# tmp->tmp
				if isinstance(stmt,pyvex.stmt.WrTmp):
					expr = stmt.data
					# reg->tmp
					if isinstance(expr,pyvex.expr.Get):
						# 污点传播
						if expr.offset in self.taint_register:
							taint_tmp[stmt.tmp] = self.taint_register[expr.offset]
						else:
							# 污点消除
							if stmt.tmp in taint_tmp:
								del taint_tmp[stmt.tmp]

					# tmp->tmp
					elif isinstance(expr,pyvex.expr.Binop):
						# tmp+const
						if expr.op == "Iop_Add64":
							child_expressions = expr.child_expressions
							# 排除以下情况：
							# t3 = Add64(0x0000000000000000,t2) 
							if isinstance(child_expressions[0],pyvex.expr.RdTmp):
								tmp = child_expressions[0].tmp
								if isinstance(child_expressions[1],pyvex.expr.RdTmp):
									tmp2 = child_expressions[1].tmp
									# 污点传播
									if (tmp in taint_tmp) and (tmp2 in taint_tmp):
										# 虚基类
										if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):
											taint_tmp[stmt.tmp] = (taint_tmp[tmp][0] + taint_tmp[tmp2],"vbase")
										else:
											if not isinstance(taint_tmp[tmp2],tuple):
												taint_tmp[stmt.tmp] = taint_tmp[tmp] + taint_tmp[tmp2]
									else:
										# 污点消除
										if stmt.tmp in taint_tmp:
											del taint_tmp[stmt.tmp]
								else:
									const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
									# 污点传播
									if tmp in taint_tmp:
										# 从vbtable获取虚基类偏移
										if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbtable"):
											taint_tmp[stmt.tmp] = (taint_tmp[tmp][0],"vbase")
										else:
											# 虚基类
											if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):
												# 排除vftable列表的情况
												if isinstance(taint_tmp[tmp][0],list):
													del taint_tmp[tmp][0]
												else:
													taint_tmp[stmt.tmp] = (taint_tmp[tmp][0] + const,"vbase")
											else:
												if isinstance(taint_tmp[tmp],int) or isinstance(taint_tmp[tmp],long):
													taint_tmp[stmt.tmp] = taint_tmp[tmp] + const
												elif (self.filetype == "ELF") and isinstance(taint_tmp[tmp],str):
													find = 0
													for VTT in self.VTT_list:
														if taint_tmp[tmp] in self.VTT_list[VTT]["addr"]:
															find = 1
															break
													if find == 1:
														taint_tmp[stmt.tmp] = hex(int(taint_tmp[tmp],16) + const).strip("L")
													else:
														del taint_tmp[tmp]
												else:
													del taint_tmp[tmp]
												
									else:
										# 污点消除
										if stmt.tmp in taint_tmp:
											del taint_tmp[stmt.tmp]
						elif expr.op == "Iop_Sub64":
							child_expressions = expr.child_expressions
							# 排除以下情况：
							# t3 = Sub64(0x0000000000000000,t2) -> neg rax  取反
							if isinstance(child_expressions[0],pyvex.expr.RdTmp):
								tmp = child_expressions[0].tmp
								# 污点传播
								if tmp in taint_tmp:
									# 40 | ------ IMark(0x154a, 3, 0) ------
									# 41 | t48 = LDle:I64(t47)
									# 42 | ------ IMark(0x154d, 4, 0) ------
									# 43 | t13 = Sub64(t48,0x0000000000000018)  <-----------
									# 44 | PUT(pc) = 0x0000000000001551
									# eg. vftable-0x18
									if self.filetype == "ELF" and isinstance(irsb.statements[i-2],pyvex.stmt.WrTmp) and isinstance(irsb.statements[i-2].data,pyvex.expr.Load):
										vftable = taint_tmp[tmp]
										for VTT in self.VTT_list:
											if vftable in self.VTT_list[VTT]["vftable"]:
												const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
												vftable_addr = int(vftable,16)
												vbase_offset_addr = vftable_addr - const
												taint_tmp[stmt.tmp] = (vbase_offset_addr,"VTT")
												break
									elif isinstance(child_expressions[1],pyvex.expr.Const):
										const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0] 
										if isinstance(taint_tmp[tmp],int) or isinstance(taint_tmp[tmp],long):
											taint_tmp[stmt.tmp] = taint_tmp[tmp] - const
										else:
											del taint_tmp[tmp]                             
								else:
									# 污点消除
									if stmt.tmp in taint_tmp:
										del taint_tmp[stmt.tmp]
						else:
							# t28 = CmpEQ8(t30,t29)
							if stmt.tmp in taint_tmp:
								del taint_tmp[stmt.tmp]

					elif isinstance(expr,pyvex.expr.Load):
						child_expressions = expr.child_expressions
						if len(child_expressions)==1:
							if isinstance(child_expressions[0],pyvex.expr.RdTmp):
								tmp = child_expressions[0].tmp
								if expr.type == "Ity_I64":
									# 污点传播
									if tmp in taint_tmp:
										# 忽略带vbase信息的元组
										if (not isinstance(taint_tmp[tmp],int)) and (not isinstance(taint_tmp[tmp],long)):
											del taint_tmp[tmp]
										else:
											offset_str = hex(taint_tmp[tmp]).strip("L")
					
										
											if offset_str in self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]:
												if self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "var":
													# 将var的值赋值
													taint_tmp[stmt.tmp] = self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"]

												elif self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "vbtable":
													# 将vbtable的地址赋值
													taint_tmp[stmt.tmp] = (self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"],"vbtable")

									else:
										# 从rsp中存储的污点寻找
										rsp_offset = self.is_rsp(function_addr_str,irsb,i,tmp)

										if (rsp_offset != None) and (rsp_offset in self.taint_rsp[function_addr_str]):
											if isinstance(self.taint_rsp[function_addr_str][rsp_offset],list):
												if len(self.taint_rsp[function_addr_str][rsp_offset]) != 0:
													reg_data = self.taint_rsp[function_addr_str][rsp_offset].pop()
											else:
												reg_data = self.taint_rsp[function_addr_str][rsp_offset]

											taint_tmp[stmt.tmp] = reg_data
											# 找到将该临时变量也标记污点，后面的的是利用这个覆写
											taint_tmp[tmp] = reg_data
										# 污点消除
										elif stmt.tmp in taint_tmp:
											del taint_tmp[stmt.tmp]
								elif expr.type == "Ity_I32":
									prev_stmt = irsb.statements[i-1]
									if isinstance(prev_stmt,pyvex.stmt.WrTmp):
										prev_expr = prev_stmt.data
										if isinstance(prev_expr,pyvex.expr.Binop) and (prev_expr.op == "Iop_Add64"):
											prev_child_expressions = prev_expr.child_expressions
											# 只有Add(tmp,0x4)的采取操作  ->  取vbtable中虚基类的偏移
											if isinstance(prev_child_expressions[1],pyvex.expr.Const) and (struct.unpack('q',struct.pack('Q',prev_child_expressions[1].con.value))[0] ==4):
												# 污点传播
												if tmp in taint_tmp:
													# 从vbtable中取出偏移
													if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):
														if taint_tmp[tmp][0] in self.vbtable_list:
															taint_tmp[stmt.tmp] = (int(self.vbtable_list[taint_tmp[tmp][0]],16),"vbase")
														else:
															del taint_tmp[tmp]
												else:
													# 污点消除
													if stmt.tmp in taint_tmp:
														del taint_tmp[stmt.tmp]

							elif isinstance(child_expressions[0],pyvex.expr.Const):
								got_addr = child_expressions[0].con.value
								if got_addr <= (self.proj.loader.main_bin.mapped_base + self.proj.loader.main_bin.max_addr):
									section_name = self.proj.loader.find_section_containing(got_addr).name
									# 处理got表获取vftable
									if section_name == ".got":
										state = self.proj.factory.blank_state()
										bv = state.mem[got_addr].uint64_t.resolved
										offsetToTop_addr = bv.args[0]
										vftable_str = hex(offsetToTop_addr+0x10).strip("L")
										if vftable_str in self.vftable_list:
											taint_tmp[stmt.tmp] = offsetToTop_addr
										else:
											# 有的从OffsetToVbase取
											vftable_str = hex(offsetToTop_addr+0x18).strip("L")
											if vftable_str in self.vftable_list:
												taint_tmp[stmt.tmp] = offsetToTop_addr
											else:
												# 污点消除
												if stmt.tmp in taint_tmp:
													del taint_tmp[stmt.tmp]
								else:
									# 污点消除
									if stmt.tmp in taint_tmp:
										del taint_tmp[stmt.tmp]
						else:
							msg = "[*]error:load expresstions length != 1"
							self.debug(irsb,stmt,ctor,taint_tmp,msg)
					elif isinstance(expr,pyvex.expr.Unop):
						if expr.op == "Iop_32Sto64":
							child_expressions = expr.child_expressions
							if len(child_expressions)==1:
								tmp = child_expressions[0].tmp
								# 污点传播
								if tmp in taint_tmp:
									if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):                                  
										taint_tmp[stmt.tmp] = (taint_tmp[tmp][0],"vbase")
								else:
									# 污点消除
									if stmt.tmp in taint_tmp:
										del taint_tmp[stmt.tmp]
							else:
								msg = "[*]error:load expresstions length != 1"
								self.debug(irsb,stmt,ctor,taint_tmp,msg)

				# const->reg
				# tmp->reg
				elif isinstance(stmt,pyvex.stmt.Put):

					expr = stmt.data
					# 若是rsp，则将self.taint_rsp的值更新
					if stmt.offset == 48:
						tmp = expr.tmp
						prev_stmt = irsb.statements[i-1]
						if isinstance(prev_stmt,pyvex.stmt.WrTmp):
							prev_expr = prev_stmt.data
							if isinstance(prev_expr,pyvex.expr.Binop):
								if prev_expr.op == "Iop_Sub64":
									next_stmt = irsb.statements[i+1]
									next_block_addr = block.capstone.insns[-1].insn.address + block.capstone.insns[-1].insn.size
									# 排除call 产生的push操作
									if isinstance(next_stmt,pyvex.stmt.Store) and isinstance(next_stmt.data,pyvex.expr.Const) and (next_stmt.data.con.value == next_block_addr):
										pass
									else:
										child_expressions = prev_expr.child_expressions
										if isinstance(child_expressions[1],pyvex.expr.Const):
											add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
											new_rsp = {}
											for offset in self.taint_rsp[function_addr_str]:
												new_rsp[offset + add_offset] = self.taint_rsp[function_addr_str][offset]
											self.taint_rsp[function_addr_str] = new_rsp
								
								# 70 | ------ IMark(0x75a33d271, 1, 0) ------
								# 71 | t17 = LDle:I64(t14)
								# 72 | t62 = Add64(t14,0x0000000000000008)
								# 73 | PUT(rsp) = t62              ←——————
								# 74 | PUT(rdi) = t17
								# 75 | PUT(pc) = 0x000000075a33d272
								# pop 操作
								

								elif prev_expr.op == "Iop_Add64":
									if i+2 < len(irsb.statements):
										next_stmt = irsb.statements[i+2]
										# 排除ret的pop操作
										if isinstance(next_stmt,pyvex.stmt.AbiHint) and irsb.jumpkind == "Ijk_Ret":
											pass
										else:
											child_expressions = prev_expr.child_expressions
											if isinstance(child_expressions[1],pyvex.expr.Const):
												add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
												new_rsp = {}
												for offset in self.taint_rsp[function_addr_str]:
													new_rsp[offset - add_offset] = self.taint_rsp[function_addr_str][offset]
												self.taint_rsp[function_addr_str] = new_rsp 
									else:
										child_expressions = prev_expr.child_expressions
										if isinstance(child_expressions[1],pyvex.expr.Const):
											add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
											new_rsp = {}
											for offset in self.taint_rsp[function_addr_str]:
												new_rsp[offset - add_offset] = self.taint_rsp[function_addr_str][offset]
											self.taint_rsp[function_addr_str] = new_rsp 

						# 63 | ------ IMark(0x75a33d26d, 4, 0) ------
						# 64 | t14 = Add64(t57,0x0000000000000030)
						# 65 | PUT(cc_op) = 0x0000000000000004
						# 66 | PUT(cc_dep1) = t57
						# 67 | PUT(cc_dep2) = 0x0000000000000030
						# 68 | PUT(rsp) = t14                  ←——————
						# 69 | PUT(pc) = 0x000000075a33d271
						# 处理add rsp,0x30 和 sub rsp,0x30

						else:
							prev_stmt_1 = irsb.statements[i-1]
							prev_stmt_2 = irsb.statements[i-2]
							prev_stmt_3 = irsb.statements[i-3]
							prev_stmt_4 = irsb.statements[i-4]
							if isinstance(prev_stmt_1,pyvex.stmt.Put) and (prev_stmt_1.offset == 160):
								if isinstance(prev_stmt_2,pyvex.stmt.Put) and (prev_stmt_2.offset == 152):
									if isinstance(prev_stmt_3,pyvex.stmt.Put) and (prev_stmt_3.offset == 144):
										if isinstance(prev_stmt_4,pyvex.stmt.WrTmp):
											prev_expr = prev_stmt_4.data
											if isinstance(prev_expr,pyvex.expr.Binop):
												if prev_expr.op == "Iop_Add64":
													child_expressions = prev_expr.child_expressions
													if isinstance(child_expressions[1],pyvex.expr.Const):
														add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
														new_rsp = {}
														for offset in self.taint_rsp[function_addr_str]:
															new_rsp[offset - add_offset] = self.taint_rsp[function_addr_str][offset]
														self.taint_rsp[function_addr_str] = new_rsp
												elif prev_expr.op == "Iop_Sub64":
													child_expressions = prev_expr.child_expressions
													if isinstance(child_expressions[1],pyvex.expr.Const):
														add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
														new_rsp = {}
														for offset in self.taint_rsp[function_addr_str]:
															new_rsp[offset + add_offset] = self.taint_rsp[function_addr_str][offset]
														self.taint_rsp[function_addr_str] = new_rsp


					# 03 | t7 = Sub64(t8,0x0000000000000008)
					# 04 | PUT(rsp) = t7
					# 05 | STle(t7) = t0
					# 06 | ------ IMark(0x75a81c176, 4, 0) ------
					# 07 | t2 = Sub64(t7,0x0000000000000020)
					# 08 | PUT(cc_op) = 0x0000000000000008
					# 09 | PUT(cc_dep1) = t7
					# 10 | PUT(cc_dep2) = 0x0000000000000020  ←——————
					# 处理sub操作没有赋值rsp的情况
					
					elif stmt.offset == 160:
						if i+1 < len(irsb.statements):					
							next_stmt = irsb.statements[i+1]
							if isinstance(next_stmt,pyvex.stmt.Put) and (next_stmt.offset == 48):
								pass
							else:
								prev_stmt_1 = irsb.statements[i-1]
								prev_stmt_2 = irsb.statements[i-2]
								prev_stmt_3 = irsb.statements[i-3]
								if isinstance(prev_stmt_1,pyvex.stmt.Put) and (prev_stmt_1.offset == 152):
									if isinstance(prev_stmt_2,pyvex.stmt.Put) and (prev_stmt_2.offset == 144):
										if isinstance(prev_stmt_3,pyvex.stmt.WrTmp):
											prev_expr = prev_stmt_3.data
											if isinstance(prev_expr,pyvex.expr.Binop):
												if prev_expr.op == "Iop_Sub64":
													child_expressions = prev_expr.child_expressions
													if isinstance(child_expressions[1],pyvex.expr.Const):
														add_offset = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
														tmp = child_expressions[0].tmp
														sub_rsp_flag = 0
														j = i - 4
														while j >= 0:
															search_stmt = irsb.statements[j]
															if isinstance(search_stmt,pyvex.stmt.Put) and (search_stmt.offset == 48):
																if search_stmt.data.tmp == tmp:
																	sub_rsp_flag = 1
																	break
															j = j - 1
														if sub_rsp_flag == 1:
															new_rsp = {}
															for offset in self.taint_rsp[function_addr_str]:
																new_rsp[offset + add_offset] = self.taint_rsp[function_addr_str][offset]
															self.taint_rsp[function_addr_str] = new_rsp

					# tmp->reg
					if isinstance(expr,pyvex.expr.RdTmp):
						tmp = expr.tmp
						# 污点传播
						if tmp in taint_tmp:
							self.taint_register[stmt.offset] = taint_tmp[tmp]
						else:
							# TODO: 若是rcx，则检查下一条指令是否是call，若是则后向切片寻找rsp offset，并污点标记rcx
							# lea     rcx, [rsp+4E8h+var_2C8] ; this
							# call    ??0StringSource@CryptoPP@@QEAA@PEBD_NPEAVBufferedTransformation@1@@Z
							if stmt.offset == 24:
								j = i + 1
								ins_count = 0
								while j < len(irsb.statements):
									next_stmt = irsb.statements[j]
									
									if isinstance(next_stmt,pyvex.stmt.IMark):
										ins_count += 1
									elif isinstance(next_stmt,pyvex.stmt.AbiHint) and (ins_count == 1):
										k = i - 1
										prev_tmp = tmp
										rcx_offset = 0
										find_rsp_rbp = False
										while k >= 0:
											prev_stmt = irsb.statements[k]
											
											if isinstance(prev_stmt,pyvex.stmt.WrTmp) and (prev_stmt.tmp == prev_tmp):
												prev_expr = prev_stmt.data
												if isinstance(prev_expr,pyvex.expr.Binop):
													if (prev_expr.op == "Iop_Add64") or (prev_expr.op == "Iop_Sub64"):
														child_expressions = prev_expr.child_expressions														
														if isinstance(child_expressions[1],pyvex.expr.Const):
															prev_tmp = child_expressions[0].tmp
															const = struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
															rcx_offset += const
												elif isinstance(prev_expr,pyvex.expr.Get):

													# rsp | rbp
													if (prev_expr.offset == 48) or (prev_expr.offset == 56):

														find_rsp_rbp = True
														self.taint_register[24] = rcx_offset
														break

											k -= 1
										if find_rsp_rbp:
											break
									j += 1
							else:
								# 从rsp中存储的污点寻找
								rsp_offset = self.is_rsp(function_addr_str,irsb,i,tmp)

								'''
								if function_addr_str == "0x75a33d1c4":
									msg = "[*]is_rsp"
									print "rsp_offset:"+str(rsp_offset)
									self.debug(irsb=irsb,stmt=stmt,msg=msg)
								'''

								if (rsp_offset != None) and (rsp_offset in self.taint_rsp[function_addr_str]):
									if isinstance(self.taint_rsp[function_addr_str][rsp_offset],list):
										if len(self.taint_rsp[function_addr_str][rsp_offset]) != 0:
											reg_data = self.taint_rsp[function_addr_str][rsp_offset].pop()
									else:
										reg_data = self.taint_rsp[function_addr_str][rsp_offset]
									self.taint_register[stmt.offset] = reg_data
									# 找到将该临时变量也标记污点，后面的的是利用这个覆写
									taint_tmp[tmp] = reg_data
								# 污点消除
								elif stmt.offset in self.taint_register:
									del self.taint_register[stmt.offset]
								'''
								# 更新rsp
								if pop == 1:
									new_rsp = {}
									for offset in self.taint_rsp[function_addr_str]:
										new_rsp[offset - 8] = self.taint_rsp[function_addr_str][offset]
									self.taint_rsp[function_addr_str] = new_rsp
								'''

					# const->reg
					elif isinstance(expr,pyvex.expr.Const):
						# 00 | ------ IMark(0x18002fdd6, 7, 0) ------
						# 01 | PUT(rbp) = 0x0000000180041b90
						# 02 | ------ IMark(0x18002fddd, 3, 0) ------
						# NEXT: PUT(rip) = 0x000000018002fde0; Ijk_Boring
						# 后面先call一个函数在进行vftable覆写就会出现这种情况
						const = expr.con.value
						const_str = hex(const).strip("L")
						if const_str in self.vftable_list:
							self.taint_register[stmt.offset] = const_str
						else:
							# 检查VTT赋值
							if self.filetype == "ELF" :
								find = 0
								for VTT in self.VTT_list:
									if const_str in self.VTT_list[VTT]["addr"]:
										self.taint_register[stmt.offset] = const_str
										find = 1
										break
								if find == 0:
									# 污点消除
									if stmt.offset in self.taint_register:
										del self.taint_register[stmt.offset]
							# 污点消除
							elif stmt.offset in self.taint_register:
								del self.taint_register[stmt.offset]

				# vftable_addr->mem[tmp]
				# vbtable_addr->mem[tmp]
				elif isinstance(stmt,pyvex.stmt.Store):
					expr = stmt.data
					if isinstance(expr,pyvex.expr.Const):
						const = stmt.data.con.value
						const_str = hex(const).strip("L")
						if const_str in self.vftable_list:
							if isinstance(stmt.addr,pyvex.expr.RdTmp):
								tmp = stmt.addr.tmp
								if tmp in taint_tmp:
									if isinstance(taint_tmp[tmp],tuple) and (taint_tmp[tmp][1] == "vbase"):
										# 排除其他函数中有new操作之后的覆写操作
										if isinstance(taint_tmp[tmp][0],list):
											pass
										else:						
											offset_str = hex(taint_tmp[tmp][0]).strip("L")
										
											if offset_str in self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]:
												if self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "var":
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vbase"
													self.vftable_num += 1

												else:
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vbase"
													self.vftable_num += 1
											else:
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str] = dict()
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vbase"
												self.vftable_num += 1
									else:
										if (not isinstance(taint_tmp[tmp],tuple)) and (not isinstance(taint_tmp[tmp],str)):
											offset_str = hex(taint_tmp[tmp]).strip("L")

											if offset_str in self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]:
												if self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "var":
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
													self.vftable_num += 1
												else:
													if (self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "vftable") and (not isinstance(self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"],list)):
														self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
														self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
														self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
														self.vftable_num += 1
													else:
														# TODO:完全内联的构造函数后面还有析构函数，在执行析构函数时出错，目前处理方法是略过
														if self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "vbtable":
															return
														else:
															self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
															self.vftable_num += 1
													# VTT 检查，看是否存在虚继承，若是，则将对应内存偏移标记成“vbase”
													if self.filetype == "ELF":
														self.VTT_check(ctor,offset_str,const_str)
											else:
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str] = dict()
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
												self.vftable_num += 1
								else:
									no_new_offset = self.find_not_new_offset(irsb,i,tmp)
									if no_new_offset != None:
										offset_str = hex(no_new_offset).strip("L")

										if offset_str in self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]:
											if self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "var":
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
												self.vftable_num += 1
											else:
												if (self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "vftable") and (not isinstance(self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"],list)):
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
													self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
													self.vftable_num += 1
												else:
													# TODO:完全内联的构造函数后面还有析构函数，在执行析构函数时出错，目前处理方法是略过
													if self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "vbtable":
														return
													else:
														self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
														self.vftable_num += 1
												# VTT 检查，看是否存在虚继承，若是，则将对应内存偏移标记成“vbase”
												if self.filetype == "ELF":
													self.VTT_check(ctor,offset_str,const_str)
										else:
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str] = dict()
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
											self.vftable_num += 1
									else:

										if "0x0" in self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]:
											# TODO: 构造函数完全内联,如何识别多个类 -> 先识别类的数量（通过污点分析各个new与vftable覆写），大于1标记full inline，之后再同一处理 Solved
											# MpEngine:0x75a296ec0
											if isinstance(self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]["0x0"]["value"],list):
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]["0x0"]["value"].append((const_str,self.vftable_num))
												self.vftable_num += 1
												# VTT 检查，看是否存在虚继承，若是，则将对应内存偏移标记成“vbase”
												if self.filetype == "ELF":
													self.VTT_check(ctor,offset_str,const_str)
										else:
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]["0x0"] = dict()
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]["0x0"]["value"] = list()
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]["0x0"]["value"].append((const_str,self.vftable_num))
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]["0x0"]["attribute"] = "vftable"
											self.multi_ctor_list[ctor+"-"+str(class_num)]["unknow"] = 1
											self.vftable_num += 1

						elif (self.filetype == "PE") and (const_str in self.vbtable_list):
							if isinstance(stmt.addr,pyvex.expr.RdTmp):
								tmp = stmt.addr.tmp
								if tmp in taint_tmp:
									# 排除其他函数中有new操作之后的覆写操作
									if not isinstance(taint_tmp[tmp],tuple):
										offset_str = hex(taint_tmp[tmp]).strip("L")

										if offset_str in self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]:
											if self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "var":
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"]= const_str
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vbtable"
											else:
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"]= const_str
										else:
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str] = dict()
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"]= const_str
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vbtable"
								else:
									# 若构造函数遍历时出现new操作和其构造函数，可能无法污点，不过其在后面的ctor_list里有，所以可以略过
									if (function_addr_str != ctor) and (function_addr_str in self.ctor_list):
										pass
									else:
										# TODO:会有遗漏
										pass
										#msg = "[*]error:multi_class vbtable leave out"
										#self.debug(irsb,stmt,ctor,taint_tmp,msg)
					# 一般将寄存器的值保存在栈变量上，保存上下文,一般在函数的第一个基本块
					elif isinstance(expr,pyvex.expr.RdTmp):
						# 忽略Const [cs:0x100000] = rax 没有作用
						if isinstance(stmt.addr,pyvex.expr.RdTmp):
							data_tmp = expr.tmp
							store_tmp = stmt.addr.tmp
							# 同时被污点标记证明有vftable写入
							if (data_tmp in taint_tmp) and (store_tmp in taint_tmp):
								if self.filetype == "ELF":
									if not isinstance(taint_tmp[data_tmp],str):
										taint_data = hex(taint_tmp[data_tmp]).strip("L")
									else:
										taint_data = taint_tmp[data_tmp]
									if taint_data in self.vftable_list:
										if isinstance(taint_tmp[store_tmp],tuple) and (taint_tmp[store_tmp][1] == "vbase"):
											if isinstance(taint_tmp[store_tmp][0],str):
												offset_str = taint_tmp[store_tmp][0]
											else:
												offset_str = hex(taint_tmp[store_tmp][0]).strip("L")
											if offset_str in self.ctor_list[ctor+"-"+str(class_num)]["this_offset"]:
												self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((taint_data,self.vftable_num))
												self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vbase"
												self.vftable_num += 1
											else:
												self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str] = dict()
												self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
												self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((taint_data,self.vftable_num))
												self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vbase"
												self.vftable_num += 1
										else:
											if isinstance(taint_tmp[store_tmp],str):
												offset_str = taint_tmp[store_tmp]
											else:
												offset_str = hex(taint_tmp[store_tmp]).strip("L")
											const_str = taint_data
											if offset_str in self.ctor_list[ctor]["this_offset"]:
												if self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "var":
													self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
													self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
													self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
													self.vftable_num += 1
												else:
													self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
													self.vftable_num += 1
											else:
												try:
													self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str] = dict()
													self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
													self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
													self.ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
													self.vftable_num += 1
												except:
													string =  ctor+"-"+str(class_num) 
													# libQuantLib.so 不知道为什么出错
													if string == "0xfa0ea0-1":
														return
													else:
														print "[*]error: Line 2892"
														sys.exit() 
								elif isinstance(taint_tmp[store_tmp],int) or isinstance(taint_tmp[store_tmp],long):
									offset_str = hex(taint_tmp[store_tmp]).strip("L")
									const_str = taint_tmp[data_tmp]
									if isinstance(const_str,str):
										if offset_str in self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]:
											if self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] == "var":
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
												self.vftable_num += 1
											else:
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
												self.vftable_num += 1
										else:
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str] = dict()
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"] = list()
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"].append((const_str,self.vftable_num))
											self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "vftable"
											self.vftable_num += 1
									else:
										# TODO:忽略不知道会遗漏什么
										pass
										#msg = "[*]error:const_str not str"
										#self.debug(irsb,stmt,ctor,taint_tmp,msg) 
								else:
									del taint_tmp[store_tmp]
							elif data_tmp in taint_tmp:
								store_tmp = stmt.addr.tmp
								if store_tmp not in taint_tmp:
									# 寻找栈变量偏移
									rsp_offset = self.find_rsp_offset(irsb,i-1,store_tmp)
									if rsp_offset != 0 :
										if rsp_offset in self.taint_rsp[function_addr_str]:
											if isinstance(self.taint_rsp[function_addr_str][rsp_offset],list):
												self.taint_rsp[function_addr_str][rsp_offset].append(taint_tmp[data_tmp])
											else:
												prev_rsp = self.taint_rsp[function_addr_str][rsp_offset]
												self.taint_rsp[function_addr_str][rsp_offset] = []
												self.taint_rsp[function_addr_str][rsp_offset].append(prev_rsp)
												self.taint_rsp[function_addr_str][rsp_offset].append(taint_tmp[data_tmp])
										else:
											self.taint_rsp[function_addr_str][rsp_offset] = taint_tmp[data_tmp]
							elif store_tmp in taint_tmp:
								# MpEngine.dll bug:同一位置上vbtable前后offset不一致，派生类虚基类offset=0x40,基类虚基类offset=0x30
								# 派生类和基类会有mov [rbx+0x30],rdi，会将之前的vftable表清掉，虽不影响程序运行结果，但是影响覆写分析
								MpEngine_bug_addr_list = [0x75a7902a8,0x75A790218,0x75A2A0180]
								if int(function_addr_str,16) in MpEngine_bug_addr_list:
									pass
								else:
									# 后向切片寻找data_tmp的值
									value = self.find_tmp_value(function_addr_str,block.addr,i-1,data_tmp)
									if value != None:
										# 忽略带vbase信息的元组
										if (not isinstance(taint_tmp[store_tmp],int)) and (not isinstance(taint_tmp[store_tmp],long)):
											pass
										else:
											offset_str = hex(taint_tmp[store_tmp]).strip("L")
											
											if offset_str in self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"]:
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"]= value
												# TODO:加下面这句会报错
												# self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "var"
											else:
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str] = dict()
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["value"]= value
												self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"][offset_str]["attribute"] = "var"
				

				'''
				if (self.flag == 1) and (function_addr_str == "0x75a33d1c4"):
					msg = "[*]debug"
					self.debug(irsb=irsb,stmt=stmt,ctor=ctor,taint_tmp=taint_tmp,msg=msg)
				'''
			
			
			'''
			if block_addr == 0x75A33B314:#0x75a9255a2: #0x75A81C19C:#
				msg = "[*]debug"
				self.debug(irsb,stmt,ctor,taint_tmp,msg)
			'''
			
			if irsb.jumpkind == "Ijk_Ret":
				return
			elif irsb.jumpkind == "Ijk_Call":
				
				# 到达新的new
				if (hierarchy == 0) and isinstance(irsb.next,pyvex.expr.Const) and (irsb.next.con.value in self.new_list):
					self.taint_register = {}
					self.taint_rsp = {}
					self.taint_rsp[ctor] = {}
					self.vftable_num = 1
					class_num += 1

					self.multi_ctor_list[ctor+"-"+str(class_num)] = {}
					self.multi_ctor_list[ctor+"-"+str(class_num)]["this_offset"] = {}
					self.multi_ctor_list[ctor+"-"+str(class_num)]["new_addr"] = self.ctor_list[ctor]["new_addr"] 
				
					# rax = offset 16
					this = 16
					self.taint_register[this] = 0
					successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
					# 异常处理函数后面没有指令
					if len(successors) == 0:
						return
					block_addr = successors[0]
					continue
				
				# 忽略syscall 和 间接函数调用  call eax call [eax]
				if ("syscall" not in self.cfg.functions[function_addr_str].nodes[block_addr]) and (not isinstance(irsb.next,pyvex.expr.RdTmp)):
					this_hierarchy = this_hierarchy + 1
					b_addr = irsb.next.con.value

					# 处理GCC下通过plt表的调用
					if self.proj.loader.find_section_containing(b_addr).name == ".plt":
						jmp_block = self.proj.factory.block(b_addr)
						jmp_irsb = jmp_block.vex
						stmt = jmp_irsb.statements[1]
						if isinstance(stmt,pyvex.stmt.WrTmp):
							expr = stmt.data
							if isinstance(expr,pyvex.expr.Load):
								child_expressions = expr.child_expressions
								if isinstance(child_expressions[0],pyvex.expr.Const):
									addr = child_expressions[0].con.value
									state = self.proj.factory.blank_state()
									bv = state.mem[addr].uint64_t.resolved
									b_addr = bv.args[0]

					if b_addr <= (self.proj.loader.main_bin.mapped_base + self.proj.loader.main_bin.max_addr):				
						func_addr_str = hex(b_addr).strip("L")
						self.taint_rsp[func_addr_str] = {}
						# TODO: this指针是否要换
						self.ctor_multi_class_analysis(ctor,func_addr_str,b_addr,this,this_hierarchy,class_num)
				successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
				# 异常处理函数后面没有指令
				if len(successors) == 0:
					return
				block_addr = successors[0]
				continue
			else:
				successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
				if len(successors) == 0:
					break
				elif len(successors) == 1:
					block_addr = successors[0]
					continue
				elif len(successors) == 2:
					
					# 检测循环，选择非循环的分支
					'''
					if "loop" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						block_addr = successors[1]
						continue
					'''
					# 选择不是noreturn的那条分支
					if "noreturn" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						if successors[0] == self.cfg.functions[function_addr_str].nodes[block_addr]["noreturn"]:
							block_addr = successors[1]
							continue
						else:
							block_addr = successors[0]
							continue
					# TODO:分支该如何污点分析    vftable都是必经点，所以寻找有vftable的分支？  目前都选择false分支
					else:
						# TODO:错误的2个分支，第一个没有
						# 0x75a31c8fa:	mov	r12d, dword ptr [rbp - 0x45]
						# 0x75a31c8fe:	mov	r9, qword ptr [rip + 0xb08e3b]
						# successors:
						# 0x75a31c90aL
						# 0x75a31c905L
						try:
							a=irsb.statements[-1].dst.value
						except:
							block_addr = successors[1]
							continue
						if successors[0] == irsb.statements[-1].dst.value:
							# 若遇到这种循环，则选择走另一条分支
							# —————————————————   ←——————
							# |              |          |
							# |              |          |
							# |              |          |
							# |              |          |
							# —————————————————         |
							#      ↓      ↓             |
							# —————————  —————————      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# —————————  ———————————jmp—— 
							if loop_flag == 1:
								block_addr = successors[0]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[1]
								continue
						else:
							if loop_flag == 1:
								block_addr = successors[1]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[0]
								continue
				# TODO:不知道为什么产生了3个分支,第一个不是
				# 0x75a150fdc:	mov	rax, qword ptr [r14 + 0x10]
				# 0x75a150fe0:	cmp	r9w, word ptr [rax + 0x18]
				# 0x75a150fe5:	jne	0x75a15101b
				# successors:
				# 0x75a4d70a2L
				# 0x75a15101bL
				# 0x75a150fe7L
				elif len(successors) == 3:
					'''
					# 检测循环，选择非循环的分支 
					if "loop" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						block_addr = successors[2]
						continue
					'''
					# 选择不是noreturn的那条分支
					if "noreturn" in self.cfg.functions[function_addr_str].nodes[block_addr]:
						if successors[1] == self.cfg.functions[function_addr_str].nodes[block_addr]["noreturn"]:
							block_addr = successors[2]
							continue
						else:
							block_addr = successors[3]
							continue
					# TODO:分支该如何污点分析    vftable都是必经点，所以寻找有vftable的分支？  目前都选择false分支
					else:
						if successors[1] == irsb.statements[-1].dst.value:
							# 若遇到这种循环，则选择走另一条分支
							# —————————————————   ←——————
							# |              |          |
							# |              |          |
							# |              |          |
							# |              |          |
							# —————————————————         |
							#      ↓      ↓             |
							# —————————  —————————      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# |       |  |       |      |
							# —————————  ———————————jmp—— 
							if loop_flag == 1:
								block_addr = successors[1]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[2]
								continue
						else:
							if loop_flag == 1:
								block_addr = successors[2]
								continue
							elif loop_flag == 2:
								# 改为随机选择，防止复杂的无限循环
								index = random.randint(0,1)
								block_addr = successors[index]
								continue
							else:
								block_addr = successors[1]
								continue

	'''			
	后向切片寻找静态对象的偏移（rsp|rbp）

	参数：
		irsb：基本块
		i：当前指令索引
		tmp：当前指令临时变量

	返回：
		offset：静态对象的偏移
	'''
	'''
	Backward slicing to find the offset of static objects (rsp|rbp)

	Args:
		irsb: basic block
		i: current instruction index
		tmp: temporary variable of the current instruction

	Return:
		offset: the offset of the static object
	'''
	def find_not_new_offset(self,irsb,i,tmp):
		offset = 0        

		j = i
		while j >= 0:
			stmt = irsb.statements[j]
			if isinstance(stmt,pyvex.stmt.WrTmp) and (tmp == stmt.tmp):
				expr = stmt.data
				if isinstance(expr,pyvex.expr.Binop):
					if expr.op == "Iop_Sub64":
						child_expressions = expr.child_expressions
						if isinstance(child_expressions[0],pyvex.expr.RdTmp):
							tmp = child_expressions[0].tmp
							offset += struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
					elif expr.op == "Iop_Add64":
						child_expressions = expr.child_expressions
						if isinstance(child_expressions[0],pyvex.expr.RdTmp):
							if isinstance(child_expressions[1],pyvex.expr.Const):
								tmp = child_expressions[0].tmp
								offset -= struct.unpack('q',struct.pack('Q',child_expressions[1].con.value))[0]
				elif isinstance(expr,pyvex.expr.Get):
					# rsp|rbp
					if (expr.offset == 48) or (expr.offset == 56):
						return offset
					else:
						return offset
			j = j - 1
		offset = None
		return offset

	'''
	对没有构造函数的vftable进行析构函数分析
	'''
	'''
	Destructor analysis of vftable without constructor
	'''
	def no_ctor_analysis(self):
		traced_vftable = []
		for ctor in self.ctor_list:
			for offset in self.ctor_list[ctor]["this_offset"]:
				if ((self.ctor_list[ctor]["this_offset"][offset]["attribute"] == "vftable") or (self.ctor_list[ctor]["this_offset"][offset]["attribute"] == "vbase")) and (isinstance(self.ctor_list[ctor]["this_offset"][offset]["value"] ,list)):
					vftable_list = self.ctor_list[ctor]["this_offset"][offset]["value"]
					for vftable in vftable_list:
						if vftable[0] not in traced_vftable:
							traced_vftable.append(vftable[0])
		i = 0
		for vftable in self.vftable_list:
			if vftable not in traced_vftable:
				dtor = self.vftable_list[vftable]["dtor"]
				if dtor != 0:
					self.ctor_list[dtor] = {}
					self.ctor_list[dtor]["this_offset"] = {}
					self.ctor_list[dtor]["dtor"] = 1

					self.taint_register = {}
					self.taint_rsp = {}
					self.taint_rsp[dtor] = {}
					self.vftable_num = 1
					if self.filetype == "PE":
						# rcx = offset 24
						this = 24 
					elif self.filetype == "ELF":
						# rdi == offset 72
						this = 72
					self.taint_register[this] = 0   
					self.overwrite_analysis(dtor,dtor,int(dtor,16),this,0)
					print "%s %s static_taint_analysis dtor completion" % (i,dtor)
					i += 1
					
					max_num = 0
					for offset in self.ctor_list[dtor]["this_offset"]:
						if ((self.ctor_list[dtor]["this_offset"][offset]["attribute"] == "vftable") or (self.ctor_list[dtor]["this_offset"][offset]["attribute"] == "vbase")) and (isinstance(self.ctor_list[dtor]["this_offset"][offset]["value"] ,list)):
							vftable_list = self.ctor_list[dtor]["this_offset"][offset]["value"]
							for vftable in vftable_list:
								num = vftable[1]
								if num > max_num:
									max_num = num

					for offset in self.ctor_list[dtor]["this_offset"]:
						if ((self.ctor_list[dtor]["this_offset"][offset]["attribute"] == "vftable") or (self.ctor_list[dtor]["this_offset"][offset]["attribute"] == "vbase")) and (isinstance(self.ctor_list[dtor]["this_offset"][offset]["value"] ,list)):
							vftable_list = self.ctor_list[dtor]["this_offset"][offset]["value"]
							new_vftable_list = []
							# 倒序，析构函数覆写顺序与构造函数相反
							for vftable in vftable_list[::-1]:
								num = max_num - vftable[1] + 1
								new_vftable_list.append((vftable[0],num))
							self.ctor_list[dtor]["this_offset"][offset]["value"] = new_vftable_list

					
	'''
	VTT检查，看是否存在虚继承，若是，则将对应内存偏移标记成“vbase”
	
	参数：
		ctor：对象内存布局索引
		offset_str：对象内存布局偏移
		vftable：检查的vftable地址
	'''
	'''
	VTT checks to see if there is virtual inheritance, if so, the corresponding memory offset is marked as "vbase"
	
	Args:
		ctor: Object memory layout index
		offset_str: Object memory layout offset
		vftable: Checked vftable address
	'''
	def VTT_check(self,ctor,offset_str,vftable):
		
		for VTT in self.VTT_list:
			# VTT 第一项是派生类的vftable，且为0x0偏移处，可通过此vftable的OffsetToBase字段来寻找虚基类偏移
			if vftable == self.VTT_list[VTT]["vftable"][0]:
				state = self.proj.factory.blank_state()
				# 若开启了RTTI是0x18，没开可能是0x10????
				vbase_field = 0x18
				while True:
					bv = state.mem[int(vftable,16)-vbase_field].uint64_t.resolved
					offset = bv.args[0]
					# 0x1000是否会产生误报
					if 8 < offset < 0x1000:
						offset_str = hex(offset).strip("L")		
						if offset_str in self.ctor_list[ctor]["this_offset"]:		
							self.ctor_list[ctor]["this_offset"][offset_str]["attribute"] = "vbase"
						else:
							break
					else:
						break
					vbase_field += 8
				break
	'''			
	从VTT中寻找vftable
	
	参数：
		addr：寻找的vftable的地址

	返回：
		vftable：寻找的vftable
	'''
	'''
	Looking for vftable from VTT
	
	Args:
		addr: the address of vftable

	Return:
		vftable: vftable
	'''
	def getVftableFromVTT(self,addr):
		vftable = None
		for VTT in self.VTT_list:
			if addr in self.VTT_list[VTT]["addr"]:
				index =  self.VTT_list[VTT]["addr"].index(addr)
				vftable = self.VTT_list[VTT]["vftable"][index]
				return vftable
		return vftable

