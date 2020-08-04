#!/usr/bin/env python
#-*-coding:utf-8-*-
'''
Author:d1nn3r
'''
import angr
import sys
import pyvex
import networkx
from networkx.algorithms import approximation
import cfg
import sys
import random
import json


'''
启发式推理

成员变量：
	proj：angr程序实例
	cfg：构造函数和析构函数及其相关函数的CFG
	ctor_list：对象内存布局列表
	vftable_list：vftable列表
	symbol_list：符号表
	ctor_tree：单个继承树列表
	inherTree：整体继承树
'''
class HeuristicReasoning:
	def __init__(self,proj,cfg,ctor_list,vftable_list,symbol_list):
		self.proj = proj
		self.cfg = cfg
		self.ctor_list = ctor_list
		self.vftable_list = vftable_list
		self.symbol_list = symbol_list
		self.ctor_tree = {}
		self.inherTree = networkx.DiGraph()

		# 每个vftable增加一项纪录与之连接的前一个vftable，即纪录继承关系
		for ctor in ctor_list:
			for offset in ctor_list[ctor]["this_offset"]:
				if ((ctor_list[ctor]["this_offset"][offset]["attribute"] == "vftable") or (ctor_list[ctor]["this_offset"][offset]["attribute"] == "vbase")) and isinstance(ctor_list[ctor]["this_offset"][offset]["value"],list):
					for i in range(len(ctor_list[ctor]["this_offset"][offset]["value"])):
						if i == 0:
							prev_vftable = 0
							vftable = self.ctor_list[ctor]["this_offset"][offset]["value"][i][0]
							num = self.ctor_list[ctor]["this_offset"][offset]["value"][i][1]
							self.ctor_list[ctor]["this_offset"][offset]["value"][i] = (vftable,num,prev_vftable)
							prev_vftable = self.ctor_list[ctor]["this_offset"][offset]["value"][i][0]
						else:
							vftable = self.ctor_list[ctor]["this_offset"][offset]["value"][i][0]
							num = self.ctor_list[ctor]["this_offset"][offset]["value"][i][1]
							self.ctor_list[ctor]["this_offset"][offset]["value"][i] = (vftable,num,prev_vftable)
							prev_vftable = self.ctor_list[ctor]["this_offset"][offset]["value"][i][0]

				#else:
				#	del self.ctor_list[ctor]["this_offset"][offset]
				#	
		

		# 继承树生成
		self.build()
		# 继承树合并
		self.combine()

	'''
	继承树生成

	1.vftable分析
	2.虚继承分析
	3.合并节点分析
	4.对象成员分析

	注意：
		predecessors为子节点
		successesors为父节点
	'''
	'''
	Inheritance tree generation

	1. vftable analysis
	2. Virtual inheritance analysis
	3. Merge node analysis
	4. Object member analysis

	note:
		predecessors are child nodes
		successesors is the parent node
	'''
	def build(self):
		i = 0 
		count = len(self.ctor_list)
		for ctor in self.ctor_list:
			self.ctor_tree[ctor] = {}
			self.ctor_tree[ctor]["tree"] = networkx.DiGraph()
			self.ctor_tree[ctor]["start"] = []
			self.ctor_tree[ctor]["end"] = []
			if "dtor" in self.ctor_list[ctor]:
				self.ctor_tree[ctor]["dtor"] = 1
			#print ctor
			# 将vftable加入继承树中
			self.vftable_analysis(ctor)
			# 将vbase加入继承树中
			self.vbase_analysis(ctor) 
			# 遍历节点检查是否有可合并的节点			
			self.check_combinable_node(ctor)
			# 成员对象分析
			self.object_analysis(ctor)


			i += 1
			print str(i)+"/"+str(count)+",ctor:"+ctor
		'''
		TODO: handle the error situation
		error = 0
		for ctor in self.ctor_tree:
			if "error" in self.ctor_tree[ctor]:
				print ctor
				error += 1
		print "error num:"+str(error)
		'''
	'''
	vftable分析

	循环从对象内存布局中取每一列的vftable，并合并同一个类的节点

	参数：
		ctor：对象内存布局索引
	'''
	'''
	vftable analysis

	Loop to take the vftable of each column from the object memory layout and merge nodes of the same class

	Args:
		ctor: Object memory layout index
	'''
	def vftable_analysis(self,ctor):
		# 取第一列vftable
		for offset in self.ctor_list[ctor]["this_offset"]:
			if (self.ctor_list[ctor]["this_offset"][offset]["attribute"] == "vftable") and isinstance(self.ctor_list[ctor]["this_offset"][offset]["value"],list) and (len(self.ctor_list[ctor]["this_offset"][offset]["value"]) >= 1):
				vftable = self.ctor_list[ctor]["this_offset"][offset]["value"][0][0]
				num = self.ctor_list[ctor]["this_offset"][offset]["value"][0][1]
				# TODO:检测是否有重复节点->一个类的对象成员的基类与这个类的基类是同一个,num保留小的
				if vftable in self.ctor_tree[ctor]["tree"].nodes:
					if num < self.ctor_tree[ctor]["tree"].nodes[vftable]["num"]:
						self.ctor_tree[ctor]["tree"].nodes[vftable]["num"] = num
				else:
					self.ctor_tree[ctor]["tree"].add_node(vftable,vftable_list=[vftable],num=num)
					# 添加起始节点
					self.ctor_tree[ctor]["start"].append(vftable)
				del self.ctor_list[ctor]["this_offset"][offset]["value"][0]
		# 循环取每一列的vftable
		while 1:
			onelayer_vftable_list = []
			for offset in self.ctor_list[ctor]["this_offset"]:
				if (self.ctor_list[ctor]["this_offset"][offset]["attribute"] == "vftable") and isinstance(self.ctor_list[ctor]["this_offset"][offset]["value"],list) and (len(self.ctor_list[ctor]["this_offset"][offset]["value"]) >= 1):
					onelayer_vftable_list.append(self.ctor_list[ctor]["this_offset"][offset]["value"][0])
					del self.ctor_list[ctor]["this_offset"][offset]["value"][0]

			if len(onelayer_vftable_list) == 0:
				break
			elif len(onelayer_vftable_list) == 1:
				vftable = onelayer_vftable_list[0][0]
				num = onelayer_vftable_list[0][1]
				prev_vftable = onelayer_vftable_list[0][2]
				
				self.ctor_tree[ctor]["tree"].add_node(vftable,vftable_list=[vftable],num=num)
				# 不能直接对vftable和prev_vftable添加边，因为有的prev_vftable可能合并在其他节点中不存在了，这样会导致增加空节点
				for vf in self.ctor_tree[ctor]["tree"].nodes(data=True):
					if prev_vftable in vf[1]["vftable_list"]:
						if self.ctor_tree[ctor]["tree"].has_edge(vftable,vf[0]) or self.ctor_tree[ctor]["tree"].has_edge(vf[0],vftable):
							pass
						else:
							self.ctor_tree[ctor]["tree"].add_edge(vftable,vf[0])
			else:
				# 计算同一层的vftable是否有相同的析构函数，或者具有相同的虚基类（vbtable），或者vftable地址相邻（未用），若是则将vftable加入vftable_list,节点合并，num取大的
				while 1:
					del_list = []

					for i in range(len(onelayer_vftable_list)):
						j = i + 1
						while j < len(onelayer_vftable_list):
							dtor1 = self.vftable_list[onelayer_vftable_list[i][0]]["dtor"] 
							dtor2 = self.vftable_list[onelayer_vftable_list[j][0]]["dtor"] 
							# 具有相同的析构函数
							# 排除相同的vftable
							if (dtor1 != 0) and (dtor2 != 0) and (dtor1 == dtor2) and (onelayer_vftable_list[i][0] != onelayer_vftable_list[j][0]):
								del_list.append(j)
							else:
								if ("virtual_inherit" in self.vftable_list[onelayer_vftable_list[i][0]]) and ("virtual_inherit" in self.vftable_list[onelayer_vftable_list[j][0]]) and ("vbtable" in self.vftable_list[onelayer_vftable_list[i][0]]) and ("vbtable" in self.vftable_list[onelayer_vftable_list[j][0]]):
									vbtable1 = self.vftable_list[onelayer_vftable_list[i][0]]["vbtable"]
									vbtable2 = self.vftable_list[onelayer_vftable_list[j][0]]["vbtable"]
									# 具有相同的vbtable，即虚基类相同
									if (vbtable1 == vbtable2) and (onelayer_vftable_list[i][0] != onelayer_vftable_list[j][0]):
										del_list.append(j)
								else:
									if ("symbol" in self.vftable_list[onelayer_vftable_list[i][0]]) and ("symbol" in self.vftable_list[onelayer_vftable_list[j][0]]):
										symbol1 = self.vftable_list[onelayer_vftable_list[i][0]]["symbol"]
										symbol2 = self.vftable_list[onelayer_vftable_list[j][0]]["symbol"]
										# 若符号相同，则属于同一类
										if (symbol1 == symbol2) and (onelayer_vftable_list[i][0] != onelayer_vftable_list[j][0]):
											del_list.append(j)
							j += 1
						if len(del_list) > 0:
							del_list.append(i)
							break
					if len(del_list) == 0:
						
						for node in onelayer_vftable_list:
							vftable = node[0]
							num = node[1]
							prev_vftable = node[2]
							self.ctor_tree[ctor]["tree"].add_node(vftable,vftable_list=[vftable],num=num)
							# 不能直接对vftable和prev_vftable添加边，因为有的prev_vftable可能合并在其他节点中不存在了，这样会导致增加空节点
							for vf in self.ctor_tree[ctor]["tree"].nodes(data=True):
								if prev_vftable in vf[1]["vftable_list"]:
									if self.ctor_tree[ctor]["tree"].has_edge(vftable,vf[0]) or self.ctor_tree[ctor]["tree"].has_edge(vf[0],vftable):
										pass
									elif vftable == vf[0]:
										pass
									else:
										self.ctor_tree[ctor]["tree"].add_edge(vftable,vf[0])
						break
					# 节点合并
					else:
						vftable_list = []
						num = 0
						prev_vftable_list = []
						del_vftable_list =[]
						for i in del_list:
							vftable = onelayer_vftable_list[i][0]
							if onelayer_vftable_list[i][1] > num:
								num = onelayer_vftable_list[i][1]
							prev_vftable = onelayer_vftable_list[i][2]
							vftable_list.append(vftable)
							prev_vftable_list.append(prev_vftable)

							del_vftable_list.append(onelayer_vftable_list[i])



						self.ctor_tree[ctor]["tree"].add_node(vftable,vftable_list=vftable_list,num=num)
						for prev_vftable in prev_vftable_list:
							# 不能直接对vftable和prev_vftable添加边，因为有的prev_vftable可能合并在其他节点中不存在了，这样会导致增加空节点
							for vf in self.ctor_tree[ctor]["tree"].nodes(data=True):
								if prev_vftable in vf[1]["vftable_list"]:
									if self.ctor_tree[ctor]["tree"].has_edge(vftable,vf[0]) or self.ctor_tree[ctor]["tree"].has_edge(vf[0],vftable):
										pass
									elif vftable == vf[0]:
										pass
									else:
										self.ctor_tree[ctor]["tree"].add_edge(vftable,vf[0])


						for del_vftable in del_vftable_list:
							onelayer_vftable_list.remove(del_vftable)

					


		

		# 添加结束节点
		predecessors = self.ctor_tree[ctor]["start"]
		for predecessor in predecessors:
			next_predecessors = list(self.ctor_tree[ctor]["tree"].predecessors(predecessor))
			count = len(next_predecessors)
			if count == 0:
				self.ctor_tree[ctor]["end"].append(predecessor)
			else:
				self.add_end_node(ctor,next_predecessors)

	'''
	递归添加结束节点
	
	参数：
		ctor：对象内存布局索引
		predecessors：子节点列表
	'''
	'''
	Add end node recursively

	Args:
		ctor: object memory layout index
		predecessors: list of child nodes
	'''
	def add_end_node(self,ctor,predecessors):
		for predecessor in predecessors:
			next_predecessors = list(self.ctor_tree[ctor]["tree"].predecessors(predecessor))
			count = len(next_predecessors)
			if count == 0:
				self.ctor_tree[ctor]["end"].append(predecessor)
				return
			else:
				self.add_end_node(ctor,next_predecessors)

	'''
	将vbase加入继承树中

	从vbase中取vftable，将其合并并添加虚继承关系

	参数：
		ctor：对象内存布局索引
	'''
	'''
	Add vbase to the inheritance tree

	Take vftable from vbase, merge it and add virtual inheritance

	Args:
		ctor: object memory layout index
	'''
	def vbase_analysis(self,ctor):	
		for offset in self.ctor_list[ctor]["this_offset"]:
			if (self.ctor_list[ctor]["this_offset"][offset]["attribute"] == "vbase") and isinstance(self.ctor_list[ctor]["this_offset"][offset]["value"],list) and (len(self.ctor_list[ctor]["this_offset"][offset]["value"]) >= 1):
				vbase = self.ctor_list[ctor]["this_offset"][offset]["value"][0][0]
				vnum = self.ctor_list[ctor]["this_offset"][offset]["value"][0][1]
				while 1:
					
					empty_flag = True
					# 如果数量大于2就取出
					if len(self.ctor_list[ctor]["this_offset"][offset]["value"]) >= 2:
						empty_flag = False

						vftable = self.ctor_list[ctor]["this_offset"][offset]["value"][1][0]
						num = self.ctor_list[ctor]["this_offset"][offset]["value"][1][1]
						#prev_vftable = self.ctor_list[ctor]["this_offset"][offset]["value"][1][2]


						
						# TODO: 启发式：先寻找num-1的节点是否在继承树中，若没有再进行下面的CFG查找
						# 有的num-1已经和别的节点合并了
						existed_vftable = self.find_vftable(ctor,num-1)

						
						if existed_vftable == None:
							# 从vftable中查询析构函数，并生成CFG，遍历CFG，查找覆写操作的vftable中第一个在继承树中存在的
							# TODO: 有的析构函数里缺少某些vftable的覆写 MpEngine.dll 0x75A796FAC
							dtor = self.vftable_list[vftable]["dtor"]
							if dtor != 0:
								dtor_addr = int(dtor,16)
								#start_points = [dtor_addr]
								# 生成CFG
								#mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1)
								# 查找覆写操作的vftable在继承树中存在的第一个
								
								existed_vftable = self.find_existed_vftable(ctor,dtor,0)
						# TODO:
						if existed_vftable == None:
							self.ctor_tree[ctor]["error"] = "vbase"
							return
						# TODO: 有的类的析构函数缺少派生类的vftable的覆写操作，只有虚基类的，这会导致vftable合并到虚基类里
						# 目前解决方案：增加一个变量prev_node记录每次被合并的节点，然后将其加入它的直接派生类的节点中
						if existed_vftable == vbase:
							predecessors = list(self.ctor_tree[ctor]["tree"].predecessors(prev_node))
							if len(predecessors) == 1:
								existed_vftable = predecessors[0]
								print "[+]info: vftable merge into vbase,vftable:%s,vbase:%s,merge node:%s" % (vftable,vbase,existed_vftable)
							else:
								print "[*]error: vftable merge into vbase,not find the real node,predecessors:%s" %  predecessors
								# 弹出
								del self.ctor_list[ctor]["this_offset"][offset]["value"][1]
								continue
						# 合并
						prev_node = existed_vftable
						vftable_list = self.ctor_tree[ctor]["tree"].nodes[existed_vftable]["vftable_list"]

						vftable_list.append(vftable)
						self.ctor_tree[ctor]["tree"].nodes[existed_vftable]["vftable_list"] = vftable_list
						if num > self.ctor_tree[ctor]["tree"].nodes[existed_vftable]["num"]:
							self.ctor_tree[ctor]["tree"].nodes[existed_vftable]["num"] = num
						
						# 检测虚基类是否加入继承树中，若没有则加入
						if vbase not in self.ctor_tree[ctor]["tree"].nodes:
							self.ctor_tree[ctor]["tree"].add_node(vbase,vftable_list=[vbase],num=vnum)
							self.ctor_tree[ctor]["tree"].add_edge(existed_vftable,vbase,virtual_inherit=1)
							if existed_vftable in self.ctor_tree[ctor]["start"]:
								self.ctor_tree[ctor]["start"].remove(existed_vftable)
								self.ctor_tree[ctor]["start"].append(vbase)
						else:
						# 检测父级与虚基类的关系，若父级没有虚继承关系，则添加虚继承关系
							has_virtual_inherit = self.is_virtual_inherit(ctor,existed_vftable,vbase)
							if has_virtual_inherit == False:
								self.ctor_tree[ctor]["tree"].add_edge(existed_vftable,vbase,virtual_inherit=1)
						# 弹出
						del self.ctor_list[ctor]["this_offset"][offset]["value"][1]




					if empty_flag:
						break


	'''
	寻找特定覆写顺序的节点 （num-1）
	
	参数：
		ctor：对象内存布局索引
		num：覆写顺序

	返回：
		existed_vftable：若找到vftable则返回vftable，否则返回None
	'''
	'''
	Find a node with a specific overwrite order (num-1)
	
	Args:
		ctor: object memory layout index
		num: Overwrite order

	Return:
		existed_vftable: return vftable if found, otherwise return None
	'''
	def find_vftable(self,ctor,num):
		existed_vftable = None
		for node in self.ctor_tree[ctor]["tree"].nodes(data=True):			
			if node[1]["num"] == num:
				existed_vftable = node[0]
				return existed_vftable
		return existed_vftable
	'''
	查找覆写操作的vftable是否在继承树中存在的第一个

	参数：
		ctor：对象内存布局索引,待检查的继承树
		dtor：寻找vftable的函数
		hierarchy：递归次数，代表函数层级

	返回：
		existed_vftable：若找到则返回vftable，否则返回None
	'''
	'''
	Find if the vftable of the overwrite operation is the first one in the inheritance tree

	Args:
		ctor: object memory layout index, inheritance tree to be checked
		dtor: find vftable functions
		hierarchy: Recursion times, representing function hierarchy

	Return:
		existed_vftable: return vftable if found, otherwise return None
	'''
	def find_existed_vftable(self,ctor,dtor,hierarchy):
		existed_vftable = None

		if hierarchy >=5:
			return existed_vftable
		this_hierarchy = hierarchy

		function_addr_str = dtor
		
		block_addr = int(dtor,16)
		traced_block = dict()
		while 1:
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

			block = self.cfg.functions[function_addr_str].nodes[block_addr]["block"]
			irsb = block.vex

			for i,stmt in enumerate(irsb.statements):
				# vftable_addr->mem[tmp]
				if isinstance(stmt,pyvex.stmt.Store):
					expr = stmt.data
					# 排除这种指令 rep stosb	byte ptr [rdi], al
					if block.capstone.insns[-1].insn.insn_name() == "stosb":
						pass
					elif isinstance(expr,pyvex.expr.Const):
						const = stmt.data.con.value
						const_str = hex(const).strip("L")
						for vf in self.ctor_tree[ctor]["tree"].nodes(data=True):
							if const_str in vf[1]["vftable_list"]:
								existed_vftable = vf[0]
								return existed_vftable
					# ELF处理got表获取vftable
					elif isinstance(expr,pyvex.expr.RdTmp):
						tmp = expr.tmp
						j = i - 1
						while j >= 0:
							flag = 0
							prev_stmt = irsb.statements[j]
							if (flag == 0) and isinstance(prev_stmt,pyvex.stmt.WrTmp):
								prev_expr = prev_stmt.data
								if (prev_stmt.tmp == tmp) and isinstance(prev_expr,pyvex.expr.Binop) and (prev_expr.op == "Iop_Add64"):
									child_expressions = prev_expr.child_expressions
									if isinstance(child_expressions[0],pyvex.expr.Const) and isinstance(child_expressions[1],pyvex.expr.RdTmp) and (child_expressions[0].con.value == 0x10):
										tmp = child_expressions[1].tmp
										flag = 1
									elif isinstance(child_expressions[1],pyvex.expr.Const) and isinstance(child_expressions[0],pyvex.expr.RdTmp) and (child_expressions[1].con.value == 0x10):
										tmp = child_expressions[0].tmp
										flag = 1
							elif (flag == 1) and isinstance(prev_stmt,pyvex.stmt.WrTmp):
								prev_expr = prev_stmt.data
								if (prev_stmt.tmp == tmp) and isinstance(prev_expr,pyvex.expr.Load):
									child_expressions = prev_expr.child_expressions
									if isinstance(child_expressions[0],pyvex.expr.Const):
										got_addr = child_expressions[0].con.value
										if got_addr <= (self.proj.loader.main_bin.mapped_base + self.proj.loader.main_bin.max_addr):
											section_name = self.proj.loader.find_section_containing(got_addr).name
											# 处理got表获取vftable
											if section_name == ".got":
												state = self.proj.factory.blank_state()
												bv = state.mem[got_addr].uint64_t.resolved
												offsetToTop_addr = bv.args[0]
												
												const_str = hex(offsetToTop_addr+0x10).strip("L")
												if const_str in self.vftable_list:
													for vf in self.ctor_tree[ctor]["tree"].nodes(data=True):
														if const_str in vf[1]["vftable_list"]:
															existed_vftable = vf[0]
															return existed_vftable
												else:
													# 有的从OffsetToVbase获取
													const_str = hex(offsetToTop_addr+0x18).strip("L")
													if const_str in self.vftable_list:
														for vf in self.ctor_tree[ctor]["tree"].nodes(data=True):
															if const_str in vf[1]["vftable_list"]:
																existed_vftable = vf[0]
																return existed_vftable
							j -= 1

			if irsb.jumpkind == "Ijk_Ret":
				return existed_vftable
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
						# TODO: this指针是否要换
						existed_vftable = self.find_existed_vftable(ctor,func_addr_str,this_hierarchy)
						if existed_vftable != None:
							return existed_vftable
				successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
				# 异常处理函数后面没有指令
				if len(successors) == 0:
					return existed_vftable
				block_addr = successors[0]
				continue
			else:
				successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
				if len(successors) == 0:
					return existed_vftable
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
	'''
	递归检测父级与虚基类的关系

	参数：
		ctor：对象内存布局索引
		vftable：待检测的vftable节点
		vbase：待检测的虚基类节点

	返回：
		has_virtual_inherit：若存在虚继承关系则返回True，否则返回False
	'''
	'''
	Recursively detect the relationship between parent and virtual base class

	Args:
		ctor: object memory layout index
		vftable: the vftable node to be detected
		vbase: the virtual base class node to be detected

	Return:
		has_virtual_inherit: returns True if there is a virtual inheritance relationship, otherwise returns False
	'''
	def is_virtual_inherit(self,ctor,vftable,vbase):
		has_virtual_inherit = False
		if self.ctor_tree[ctor]["tree"].has_predecessor(vbase,vftable):
			has_virtual_inherit = True
			return has_virtual_inherit
		successors = list(self.ctor_tree[ctor]["tree"].successors(vftable))
		for successor in successors:
			has_virtual_inherit = self.is_virtual_inherit(ctor,successor,vbase)
			if has_virtual_inherit:
				return has_virtual_inherit
		return has_virtual_inherit

	'''
	成员对象分析

	转换成无向图检测连通性寻找孤立节点或节点树，并通过覆写顺序来建立对象成员关系

	参数：
		ctor：对象内存布局索引
	'''
	'''
	Member Object Analysis

	Convert to undirected graph to detect connectivity to find isolated nodes or node trees, and establish object membership by overriding the order

	Args:
		ctor: object memory layout index
	'''
	def object_analysis(self,ctor):	
		
		
		if "error" in self.ctor_tree[ctor]:
			return	
		while 1:
			combine_complation = False
			start_list = self.ctor_tree[ctor]["start"]
			if len(start_list) <= 1:
				break
			for i in range(len(start_list)):
				j = i + 1
				combine_flag = False
				
				while j < len(start_list):

					# 先转换成无向图，然后检测连通性，查找是否存在孤立节点或子树
					if not approximation.local_node_connectivity(self.ctor_tree[ctor]["tree"].to_undirected(),start_list[i],start_list[j]):
						# 对象成员合并
						# num小的为主继承树(combine_tree1)
						if self.ctor_tree[ctor]["tree"].nodes[start_list[i]]["num"] < self.ctor_tree[ctor]["tree"].nodes[start_list[j]]["num"]:
							combine_tree = start_list[i]
							start_node = start_list[j]
						else:
							combine_tree = start_list[j]
							start_node = start_list[i]

						# 自上而下查找combine1中是否有节点的析构函数中的vftable在start_node节点中的vftable_list里，若有则合并，并返回True
						is_combine = self.combine_subtree(ctor,[combine_tree],start_node)

						# 若合并，标记标志变量并做删除操作
						if is_combine:
							combine_flag = True
							combine_complation = False
							# 删除被合并的节点在end和start的内容
							self.ctor_tree[ctor]["start"].remove(start_node)
							# 查找combine_tree2的结束节点
							end_node = self.find_end_node(ctor,start_node)
							if end_node in self.ctor_tree[ctor]["end"]:
								
								self.ctor_tree[ctor]["end"].remove(end_node)
							break
					j += 1
				if combine_flag:
					break
				else:
					combine_complation = True
			if combine_complation:
				break
	'''
	查找起始节点
	
	参数：
		ctor：对象内存布局索引
		node：追踪节点

	返回：
		start_node：若找到则返回起始节点，否则返回None
	'''
	'''
	Find the starting node
	
	Args:
		ctor: object memory layout index
		node: tracking node

	Return:
		start_node: If found, it returns the starting node, otherwise it returns None
	'''
	def find_start_node(self,ctor,node):
		start_node = None
		successors = list(self.ctor_tree[ctor]["tree"].successors(node))
		if len(successors) == 0:
			start_node = node
			return start_node
		else:
			for successor in successors:
				start_node = self.find_start_node(ctor,successor)
				if start_node != None:
					return start_node
		return start_node

	'''
	查找结束节点

	参数：
		ctor：对象内存布局索引
		node：追踪节点

	返回：
		end_node：若找到则返回结束节点，否则返回None
	'''
	'''
	Find end node

	Args:
		ctor: object memory layout index
		node: tracking node

	Return:
		end_node: if found, it returns the end node, otherwise it returns None
	'''
	def find_end_node(self,ctor,node):
		end_node = None
		predecessors = list(self.ctor_tree[ctor]["tree"].predecessors(node))

		if len(predecessors) == 0:
			end_node = node
			return end_node
		else:
			for predecessor in predecessors:
				end_node = self.find_end_node(ctor,predecessor)
				if end_node != None:
					return end_node
		return end_node

	'''	
	自上而下查找是否有节点的析构函数中的vftable在target_node节点中的vftable_list里，若有则合并，并返回True

	参数：
		ctor：对象内存布局索引
		node_list：节点列表
		target_node：待检测节点

	返回：
		is_combine：若有节点的析构函数中的vftable在target_node节点中的vftable_list里则返回True，否则返回False

	广度优先算法
	'''
	'''
	From top to bottom, find if there is a node's destructor vftable in the target_node node's vftable_list, if there is, then merge and return True

	Args:
		ctor: object memory layout index
		node_list: node list
		target_node: node to be detected

	Return:
		is_combine: If the vftable in the destructor of a node is in the vftable_list in the target_node, return True, otherwise return False

	Breadth First Algorithm
	'''
	def combine_subtree(self,ctor,node_list,target_node):

		is_combine = False
		next_node_list = []
		for node in node_list:
			is_combine = self.has_target_node(ctor,node,target_node)
			if is_combine:
				return is_combine
			else:
				predecessors = list(self.ctor_tree[ctor]["tree"].predecessors(node))
				next_node_list.extend(predecessors)
		if len(next_node_list) != 0:
			is_combine = self.combine_subtree(ctor,next_node_list,target_node)
		return is_combine

	'''
	查看该节点的析构函数中的vftable是否在target_node节点中的vftable_list里，若有则合并，并返回True
	
	参数：
		ctor：对象内存布局索引
		node：节点列表中的一个节点
		target_node：待检测节点

	返回：
		is_combine：若该节点的析构函数中的vftable在target_node节点中的vftable_list里则返回True并进行节点合并，否则返回False
	'''
	'''
	Check whether the vftable in the destructor of this node is in the vftable_list in the target_node node, if there is, merge them and return True
	
	Args:
		ctor: object memory layout index
		node: a node in the node list
		target_node: node to be detected

	Return:
		is_combine: If the vftable in the destructor of the node is in the vftable_list in the target_node node, return True and merge the nodes, otherwise return False
	'''
	def has_target_node(self,ctor,node,target_node):
		is_combine = False
		vftable_list = self.ctor_tree[ctor]["tree"].nodes[node]["vftable_list"]
		dtor = None
		for vftable in vftable_list:
			if self.vftable_list[vftable]["dtor"] != 0:
				dtor = self.vftable_list[vftable]["dtor"]
				break

		# TODO: 有的vftable_list里的dtor为0
		if dtor == None:
			return is_combine

		dtor_addr = int(dtor,16)
		start_points = [dtor_addr]
		# TODO:生成CFG 后期可以优化，已经生成的直接用
		#mycfg = cfg.CFG(proj=self.proj,start_points=start_points,symbol_list=self.symbol_list,thread_num=1)
		# 从CFG中寻找
		is_combine = self.find_target_node(ctor,dtor,target_node,0)
		
		if is_combine:
			# 合并
			self.ctor_tree[ctor]["tree"].add_edge(node,target_node,object_member=1)
			return is_combine
		return is_combine

	'''
	递归寻找vftable是否在target_node节点中的vftable_list里，若有则返回True
	
	参数：
		ctor：对象内存布局索引
		dtor：待分析的函数
		target_node：待检测的节点
		hierarchy：递归次数，代表函数层级

	返回：
		find：若找到则返回True，否则返回False
	'''
	'''
	Recursively find if the vftable is in the vftable_list in the target_node node, and return True if there is
	
	Args:
		ctor: object memory layout index
		dtor: function to be analyzed
		target_node: the node to be detected
		hierarchy: Recursion times, representing function hierarchy

	Return:
		find: returns True if found, otherwise returns False
	'''
	def find_target_node(self,ctor,dtor,target_node,hierarchy):

		find = False
		if hierarchy > 5:
			return find
		function_addr_str = dtor

		block_addr = int(dtor,16)
		traced_block = dict()
		while 1:
			
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
					return find

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

			for i,stmt in enumerate(irsb.statements):
				# vftable_addr->mem[tmp]
				if isinstance(stmt,pyvex.stmt.Store):
					expr = stmt.data
					# 排除这种指令 rep stosb	byte ptr [rdi], al
					if block.capstone.insns[-1].insn.insn_name() == "stosb":
						pass
					elif isinstance(expr,pyvex.expr.Const):
						const = stmt.data.con.value
						const_str = hex(const).strip("L")
						if const_str in self.ctor_tree[ctor]["tree"].nodes[target_node]["vftable_list"]:
							find = True
							return find
					# ELF处理got表获取vftable
					elif isinstance(expr,pyvex.expr.RdTmp):
						tmp = expr.tmp
						j = i - 1
						while j >= 0:
							flag = 0
							prev_stmt = irsb.statements[j]
							if (flag == 0) and isinstance(prev_stmt,pyvex.stmt.WrTmp):
								prev_expr = prev_stmt.data
								if (prev_stmt.tmp == tmp) and isinstance(prev_expr,pyvex.expr.Binop) and (prev_expr.op == "Iop_Add64"):
									child_expressions = prev_expr.child_expressions
									if isinstance(child_expressions[0],pyvex.expr.Const) and isinstance(child_expressions[1],pyvex.expr.RdTmp) and (child_expressions[0].con.value == 0x10):
										tmp = child_expressions[1].tmp
										flag = 1
									elif isinstance(child_expressions[1],pyvex.expr.Const) and isinstance(child_expressions[0],pyvex.expr.RdTmp) and (child_expressions[1].con.value == 0x10):
										tmp = child_expressions[0].tmp
										flag = 1
							elif (flag == 1) and isinstance(prev_stmt,pyvex.stmt.WrTmp):
								prev_expr = prev_stmt.data
								if (prev_stmt.tmp == tmp) and isinstance(prev_expr,pyvex.expr.Load):
									child_expressions = prev_expr.child_expressions
									if isinstance(child_expressions[0],pyvex.expr.Const):
										got_addr = child_expressions[0].con.value
										if got_addr <= (self.proj.loader.main_bin.mapped_base + self.proj.loader.main_bin.max_addr):
											section_name = self.proj.loader.find_section_containing(got_addr).name
											# 处理got表获取vftable
											if section_name == ".got":
												state = self.proj.factory.blank_state()
												bv = state.mem[got_addr].uint64_t.resolved
												offsetToTop_addr = bv.args[0]
												
												const_str = hex(offsetToTop_addr+0x10).strip("L")
												if const_str in self.vftable_list:
													if const_str in self.ctor_tree[ctor]["tree"].nodes[target_node]["vftable_list"]:
														find = True
														return find
												else:
													const_str = hex(offsetToTop_addr+0x18).strip("L")
													if const_str in self.vftable_list:
														if const_str in self.ctor_tree[ctor]["tree"].nodes[target_node]["vftable_list"]:
															find = True
															return find
							j -= 1

			#print function_addr_str,hex(block_addr)

			if irsb.jumpkind == "Ijk_Ret":
				return find
			elif irsb.jumpkind == "Ijk_Call":
				# 有的析构函数的是删除析构函数，需要再下一层
				# 忽略syscall 和 间接函数调用  call eax call [eax]
				if ("syscall" not in self.cfg.functions[function_addr_str].nodes[block_addr]) and (not isinstance(irsb.next,pyvex.expr.RdTmp)):
					this_hierarchy = hierarchy + 1
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
						find = self.find_target_node(ctor,func_addr_str,target_node,this_hierarchy)
						if find:
							return find
				# ELFTODO: 不知道为什么不在function中，查询cfg是在的
				try:
					successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
				except:
					print "block %s not in function %s" % (hex(block_addr),function_addr_str)
					return find
				# 异常处理函数后面没有指令
				if len(successors) == 0:
					return find
				block_addr = successors[0]
				continue
			else:
				successors = list(self.cfg.functions[function_addr_str].successors(block_addr))
				if len(successors) == 0:
					return find
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

		return find

	'''
	遍历节点检查是否有可合并的节点
	
	具有相同的析构函数的节点可合并

	参数：
		ctor：对象内存布局索引
	'''
	#TODO: 对于某些复杂结构可能无法合并，比如一个类继承了一个虚继承的类和一个多继承的类，这个类可能依然被识别成两个类（因为有dtor的虚基类可能被错误分到了多继承的类节点中，导致有一方没有dtor）
	'''
	Traverse the nodes to check if there are mergeable nodes
	
	Nodes with the same destructor can be merged
	
	Args:
		ctor: object memory layout index
	'''
	def check_combinable_node(self,ctor):

		while 1:
			combine_complation = True
			del_list = []
			for i,node in enumerate(self.ctor_tree[ctor]["tree"].nodes):
				combine_flag = False
				dtor = None
				# 寻找一个不为0的析构函数
				for vftable in self.ctor_tree[ctor]["tree"].nodes[node]["vftable_list"]:
					if self.vftable_list[vftable]["dtor"] != 0:
						dtor = self.vftable_list[vftable]["dtor"]
						break
				if dtor == None:
					continue
				for j,node2 in enumerate(self.ctor_tree[ctor]["tree"].nodes):
					if i != j:

						dtor2 = None
						# 寻找一个不为0的析构函数
						for vftable2 in self.ctor_tree[ctor]["tree"].nodes[node2]["vftable_list"]:
							if self.vftable_list[vftable2]["dtor"] != 0:
								dtor2 = self.vftable_list[vftable2]["dtor"]
								break
						# 若析构函数相同则进行合并操作
						if dtor == dtor2:
								
							# 保留num大的节点，删除另一个
							num1 = self.ctor_tree[ctor]["tree"].nodes[node]["num"]
							num2 = self.ctor_tree[ctor]["tree"].nodes[node2]["num"]

							vftable_list = []
							vftable_list1 = self.ctor_tree[ctor]["tree"].nodes[node]["vftable_list"]
							vftable_list2 = self.ctor_tree[ctor]["tree"].nodes[node2]["vftable_list"]
							vftable_list.extend(vftable_list1)
							vftable_list.extend(vftable_list2)

							if num1 > num2:
								# 检测合并后是否出现双向箭头，若存在则不合并  A -> C  , B <- C =>  A <-> C
								successors = self.ctor_tree[ctor]["tree"].successors(node2)
								predecessors = self.ctor_tree[ctor]["tree"].predecessors(node)
								double_flag = False
								for successor in successors: 
									if successor in predecessors:
										double_flag = True
										break
								# 两节点直接相连,证明有继承关系，是两个不同的类
								if self.ctor_tree[ctor]["tree"].has_edge(node,node2) or self.ctor_tree[ctor]["tree"].has_edge(node2,node):
									double_flag = True
								if double_flag:
									continue
								# 复制边
								self.ctor_tree[ctor]["tree"].nodes[node]["vftable_list"] = vftable_list
								successors = self.ctor_tree[ctor]["tree"].successors(node2)
								for successor in successors:
									edge_attr = self.ctor_tree[ctor]["tree"].edges[(node2,successor)]
									self.ctor_tree[ctor]["tree"].add_edges_from([(node,successor,edge_attr)])
								# 删除节点
								del_list.append(node2)

							else:
								# 检测合并后是否出现双向箭头，若存在则不合并  A -> C  , B <- C =>  A <-> C
								successors = self.ctor_tree[ctor]["tree"].successors(node)
								predecessors = self.ctor_tree[ctor]["tree"].predecessors(node2)
								double_flag = False
								for successor in successors: 
									if successor in predecessors:
										double_flag = True
										break
								# 两节点直接相连,证明有继承关系，是两个不同的类
								if self.ctor_tree[ctor]["tree"].has_edge(node,node2) or self.ctor_tree[ctor]["tree"].has_edge(node2,node):
									double_flag = True
								if double_flag:
									continue
								# 复制边
								self.ctor_tree[ctor]["tree"].nodes[node2]["vftable_list"] = vftable_list
								successors = self.ctor_tree[ctor]["tree"].successors(node)
								for successor in successors:
									edge_attr = self.ctor_tree[ctor]["tree"].edges[(node,successor)]
									self.ctor_tree[ctor]["tree"].add_edges_from([(node2,successor,edge_attr)])
								# 删除节点
								del_list.append(node)
							combine_flag = True
							combine_complation = False
							break
				if combine_flag:
					break							

			if combine_complation:
				break
			else:
				# 删除节点
				for node in del_list:
					self.ctor_tree[ctor]["tree"].remove_node(node)
					# 若在start或者end列表中，则删除
					if node in self.ctor_tree[ctor]["start"]:
						self.ctor_tree[ctor]["start"].remove(node)
					if node in self.ctor_tree[ctor]["end"]:
						self.ctor_tree[ctor]["end"].remove(node)


	# 对每个ctor绘图
	'''
	def draw_ctor(self):
		import matplotlib.pyplot as plt
		import networkx as nx
		import os

		for ctor in self.ctor_tree:
			if ("multi_class" in self.ctor_list[ctor]) or ("no_new" in self.ctor_list[ctor]):
				continue

			plt.figure(figsize=(30,20))
			G = self.ctor_tree[ctor]["tree"]
			pos = nx.layout.spring_layout(G)
			nodes = nx.draw_networkx_nodes(G,pos,node_color="blue")
			edges = nx.draw_networkx_edges(G,pos, arrowsize=50,arrowstyle="->",edge_cmap=plt.cm.Blues)

			node_labels = {node[0]: node for node in G.nodes(data=True)}
			labels = nx.draw_networkx_labels(G,pos,node_labels,font_color="red")
			edge_labels = nx.draw_networkx_edge_labels(G,pos,font_color="blue")

			ax = plt.gca()
			ax.set_axis_off()
			path = os.getcwd()
			if not os.path.exists(path+"/img"):
				os.makedirs(path+"/img")
			plt.savefig('./img/'+ctor+'.png')
			plt.close('all')

		print "[+]log:draw completion"
	'''
	'''
	调试模式

	可对每个单个的继承树绘图以观察结果
	'''
	'''
	Debug mode

	Each individual inheritance tree can be plotted to observe the results
	'''
	def draw_ctor(self):
		import os
		from graphviz import Digraph
		for ctor in self.ctor_tree:
			nodetree = Digraph(ctor, node_attr={'shape': 'plaintext'})
			nodetree.attr(rankdir="BT")
			for node in self.ctor_tree[ctor]["tree"].nodes(data=True):
				vftable_list = node[1]["vftable_list"]
				function_list = []
				for vftable in vftable_list:
					function_list.extend(self.vftable_list[vftable]["functions"])

				if "symbol" in node[1]:
					name = node[1]["symbol"]
				else:
					name = node[0]
				object_member_list = []
				successors = list(self.ctor_tree[ctor]["tree"].successors(node[0]))
				for successor in successors:
					if "object_member" in self.ctor_tree[ctor]["tree"].edges[(node[0],successor)]:
						if "symbol" in self.ctor_tree[ctor]["tree"].nodes[successor]:
							if self.ctor_tree[ctor]["tree"].nodes[successor]["symbol"] not in object_member_list:
								object_member_list.append(self.ctor_tree[ctor]["tree"].nodes[successor]["symbol"])
						else:
							if successor not in object_member_list:
								object_member_list.append(successor)
				label = '<<TABLE BORDER="0" CELLBORDER="1" CELLPADDING="5" CELLSPACING="0"><TR><TD><B>'
	  			label += name
	  			label += '</B></TD></TR><TR><TD ALIGN="LEFT" BALIGN="LEFT" >'
				i = 0
				for object_name in object_member_list:
					if i!=0:
						label += "<BR/>"
					label += object_name
					i += 1
				label += '</TD></TR><TR><TD ALIGN="LEFT" BALIGN="LEFT" >'
				i = 0
				for function_addr in function_list:
					if i!=0:
						label += "<BR/>"
					label += function_addr
					i += 1
				label += '</TD></TR></TABLE>>'

				nodetree.node(node[0],label)

				successors = self.ctor_tree[ctor]["tree"].successors(node[0])
				for successor in successors:
					if "virtual_inherit" in self.inherTree.edges[(node[0],successor)]:
						nodetree.edge(node[0],successor,"virtual_inherit",arrowhead='onormal')
					elif "object_member" in self.inherTree.edges[(node[0],successor)]:
						#nodetree.attr('edge',style='dashed')
						nodetree.edge(node[0],successor,"object_member",arrowhead='vee')
						#nodetree.edge(node[0],successor,arrowhead='vee')
						#nodetree.attr('edge',style='solid')
					else:
						nodetree.edge(node[0],successor,arrowhead='onormal')
			path = os.getcwd()
			if not os.path.exists(path+"/ctor_img"):
				os.makedirs(path+"/ctor_img")
			nodetree.save(directory=path+"/ctor_img")
			nodetree.render()
			#nodetree.view()
		print "[+]log: Draw completion"
	# 对一个ctor绘图
	'''
	def draw_one(self,ctor):
		import matplotlib.pyplot as plt
		import networkx as nx
		plt.figure(figsize=(30,20))
		G = self.ctor_tree[ctor]["tree"]
		pos = nx.layout.spring_layout(G)
		nodes = nx.draw_networkx_nodes(G,pos,node_color="blue")
		edges = nx.draw_networkx_edges(G,pos, arrowsize=50,arrowstyle="->",edge_cmap=plt.cm.Blues)

		node_labels = {node[0]: node for node in G.nodes(data=True)}
		labels = nx.draw_networkx_labels(G,pos,node_labels,font_color="red")
		edge_labels = nx.draw_networkx_edge_labels(G,pos,font_color="blue")

		ax = plt.gca()
		ax.set_axis_off()

		plt.show()
	'''
	'''
	调试模式

	可对特定继承树绘图观察结果变化

	参数：
		ctor：对象内存布局索引
	'''
	'''
	Debug mode

	Ability to draw and observe changes in the results of specific inheritance

	Args:
		ctor: object memory layout index
	'''
	def draw_one(self,ctor):
		from graphviz import Digraph
		nodetree = Digraph(ctor, node_attr={'shape': 'plaintext'})
		nodetree.attr(rankdir="BT")
		for node in self.ctor_tree[ctor]["tree"].nodes(data=True):
			vftable_list = node[1]["vftable_list"]
			function_list = []
			for vftable in vftable_list:
				function_list.extend(self.vftable_list[vftable]["functions"])
					
			if "symbol" in node[1]:
				name = node[1]["symbol"]
			else:
				name = node[0]
			object_member_list = []
			successors = list(self.ctor_tree[ctor]["tree"].successors(node[0]))
			for successor in successors:
				if "object_member" in self.ctor_tree[ctor]["tree"].edges[(node[0],successor)]:
					if "symbol" in self.ctor_tree[ctor]["tree"].nodes[successor]:
						if self.ctor_tree[ctor]["tree"].nodes[successor]["symbol"] not in object_member_list:
							object_member_list.append(self.ctor_tree[ctor]["tree"].nodes[successor]["symbol"])
					else:
						if successor not in object_member_list:
							object_member_list.append(successor)
			label = '<<TABLE BORDER="0" CELLBORDER="1" CELLPADDING="5" CELLSPACING="0"><TR><TD><B>'
  			label += name
  			label += '</B></TD></TR><TR><TD ALIGN="LEFT" BALIGN="LEFT" >'
			i = 0
			for object_name in object_member_list:
				if i!=0:
					label += "<BR/>"
				label += object_name
				i += 1
			label += '</TD></TR><TR><TD ALIGN="LEFT" BALIGN="LEFT" >'
			i = 0
			for function_addr in function_list:
				if i!=0:
					label += "<BR/>"
				label += function_addr
				i += 1
			label += '</TD></TR></TABLE>>'

			nodetree.node(node[0],label)

			successors = self.ctor_tree[ctor]["tree"].successors(node[0])
			for successor in successors:
				if "virtual_inherit" in self.ctor_tree[ctor]["tree"].edges[(node[0],successor)]:
					nodetree.edge(node[0],successor,"virtual_inherit",arrowhead='onormal')
				elif "object_member" in self.ctor_tree[ctor]["tree"].edges[(node[0],successor)]:
					#nodetree.attr('edge',style='dashed')
					nodetree.edge(node[0],successor,"object_member",arrowhead='vee')
					#nodetree.edge(node[0],successor,arrowhead='vee')
					#nodetree.attr('edge',style='solid')
				else:
					nodetree.edge(node[0],successor,arrowhead='onormal')
		#nodetree.save(directory="./ctor_img")
		#nodetree.render()
		nodetree.view()
		print "[+]log: Draw completion"

	# 对继承树绘图
	'''
	def draw(self):
		import matplotlib.pyplot as plt
		import networkx as nx
		plt.figure(figsize=(30,20))
		G = self.inherTree
		pos = nx.layout.spring_layout(G)
		nodes = nx.draw_networkx_nodes(G,pos,node_color="blue")
		edges = nx.draw_networkx_edges(G,pos, arrowsize=50,arrowstyle="->",edge_cmap=plt.cm.Blues)

		node_labels = {node[0]: node for node in G.nodes(data=True)}
		labels = nx.draw_networkx_labels(G,pos,node_labels,font_color="red")
		edge_labels = nx.draw_networkx_edge_labels(G,pos,font_color="blue")

		ax = plt.gca()
		ax.set_axis_off()

		plt.savefig('./inherTree.png')
		print "[+]log:draw completion"
	'''
	'''
	对整个继承树进行绘图，生成.gv和.pdf文件
	'''
	'''
	Draw the entire inheritance tree and generate .gv and .pdf files
	'''
	def draw(self):
		from graphviz import Digraph
		nodetree = Digraph('NodeTree', node_attr={'shape': 'plaintext'})
		nodetree.attr(rankdir="BT")
		for node in self.inherTree.nodes(data=True):
			function_list = node[1]["function_list"]
			if "symbol" in node[1]:
				name = node[1]["symbol"]
			else:
				name = node[0]
			object_member_list = []
			successors = list(self.inherTree.successors(node[0]))
			for successor in successors:
				if "object_member" in self.inherTree.edges[(node[0],successor)]:
					if "symbol" in self.inherTree.nodes[successor]:
						if self.inherTree.nodes[successor]["symbol"] not in object_member_list:
							object_member_list.append(self.inherTree.nodes[successor]["symbol"])
					else:
						if successor not in object_member_list:
							object_member_list.append(successor)
			label = '<<TABLE BORDER="0" CELLBORDER="1" CELLPADDING="5" CELLSPACING="0"><TR><TD><B>'
  			label += name
  			label += '</B></TD></TR><TR><TD ALIGN="LEFT" BALIGN="LEFT" >'
			i = 0
			for object_name in object_member_list:
				if i!=0:
					label += "<BR/>"
				label += object_name
				i += 1
			label += '</TD></TR><TR><TD ALIGN="LEFT" BALIGN="LEFT" >'
			i = 0
			for function_addr in function_list:
				if i!=0:
					label += "<BR/>"
				label += function_addr
				i += 1
			label += '</TD></TR></TABLE>>'

			nodetree.node(node[0],label)

			successors = self.inherTree.successors(node[0])
			for successor in successors:
				if "virtual_inherit" in self.inherTree.edges[(node[0],successor)]:
					nodetree.edge(node[0],successor,"virtual_inherit",arrowhead='onormal')
				elif "object_member" in self.inherTree.edges[(node[0],successor)]:
					#nodetree.attr('edge',style='dashed')
					nodetree.edge(node[0],successor,"object_member",arrowhead='vee')
					#nodetree.edge(node[0],successor,arrowhead='vee')
					#nodetree.attr('edge',style='solid')
				else:
					nodetree.edge(node[0],successor,arrowhead='onormal')
		nodetree.save()
		nodetree.render()
		#nodetree.view()
		print "[+]log: Draw completion"

	'''
	对结果进行统计，并将结果保存到result文件中
	'''
	'''
	Count the results and save the results to the "result" file
	'''
	def statistics(self):
		class_count = 0
		dtor_count = 0
		vftable_count = 0
		no_inher = 0
		single_inher = 0
		multi_inher = 0
		virtual_inher = 0
		object_member = 0
		traced_vftable = []
		for node in self.inherTree.nodes(data=True):
			vftable_list = node[1]["vftable_list"]
			for vftable in vftable_list:
				if vftable not in traced_vftable:	
					traced_vftable.append(vftable)				
					vftable_count += 1
			if "dtor" in node[1]:
				dtor_count += 1
			class_count += 1
			successors = list(self.inherTree.successors(node[0]))
			inher_count = len(successors)
			find_object_flag = False
			for successor in successors:
				if "object_member" in self.inherTree.edges[(node[0],successor)]:
					find_object_flag = True
					inher_count -= 1
			if find_object_flag:
				object_member += 1
			if inher_count == 0:
				no_inher += 1
			elif inher_count == 1:
				single_inher += 1
			elif inher_count > 1:
				multi_inher += 1
			for successor in successors:
				'''
				# 统计包含虚继承的数量
				find = self.find_virtual_inher(node[0],successor)
				if find:
					virtual_inher += 1
					break
				'''
				# 只统计继承虚基类的数量
				if "virtual_inherit" in self.inherTree.edges[(node[0],successor)]:
					virtual_inher += 1
					break
				
		print "Analysis result:"
		print "vftable_num:"+str(vftable_count)
		print "class_num:"+str(class_count)
		print "class_num_by_dtor:"+str(dtor_count)
		print "class_num_by_ctor:"+str(class_count - dtor_count)
		print "no_inher:"+str(no_inher)
		print "single_inher:"+str(single_inher)
		print "multi_inher:"+str(multi_inher)
		print "virtual_inher:"+str(virtual_inher)
		print "object_member:"+str(object_member)

		result_file = open("result","w")
		result_file.write("vftable_num:"+str(vftable_count)+"\n")
		result_file.write("class_num:"+str(class_count)+"\n")
		result_file.write("class_num_by_dtor:"+str(dtor_count)+"\n")
		result_file.write("class_num_by_ctor:"+str(class_count - dtor_count)+"\n")
		result_file.write("no_inher:"+str(no_inher)+"\n")
		result_file.write("single_inher:"+str(single_inher)+"\n")
		result_file.write("multi_inher:"+str(multi_inher)+"\n")
		result_file.write("virtual_inher:"+str(virtual_inher)+"\n")
		result_file.write("object_member:"+str(object_member)+"\n")
		result_file.close()

	'''
	递归寻找继承树中的虚继承关系

	参数：
		src：节点1
		dst：节点2

	返回：
		find：若找到虚继承关系则返回True，否则返回False
	'''
	# TODO: 有的分析结果可能使得该函数陷入无限递归中，可能是分析结果哪里有问题
	'''
	Recursively find the virtual inheritance relationship in the inheritance tree

	Args:
		src: node 1
		dst: node 2

	Return:
		find: Returns True if a virtual inheritance relationship is found, otherwise returns False
	'''
	def find_virtual_inher(self,src,dst):
		find = False

		if "virtual_inherit" in self.inherTree.edges[(src,dst)]:
			find = True
			return find
		else:
			successors = list(self.inherTree.successors(dst))
			for successor in successors:
				if "object_member" in self.inherTree.edges[(dst,successor)]:
					continue
				
				find = self.find_virtual_inher(dst,successor)
				
				if find:
					return find
		return find

	'''
	将继承树转换成json格式

	数据格式：
		classname：类名，dict
			base：基类类名，list
			addr：类地址，以某个vftable地址为代表
			function_list：类成员函数，list
			dtor:若该类通过析构函数分析则为1，否则该项不存在
			object_member：对象成员类名，若不存在则该项不存在，list
			virtual_inherit：虚基类类领，若不存在则该项不存在，list
	'''
	'''
	Convert inheritance tree to json format

	Data Format:
		classname: class name, dict
			base: base class name, list
			addr: class address, represented by a vftable address
			function_list: class member function, list
			dtor: 1 if the class is analyzed by the destructor, otherwise the item does not exist
			object_member: object member class name, if it does not exist, the item does not exist, list
			virtual_inherit: virtual base class leader, if it does not exist, the item does not exist, list
	'''
	def gen_json(self):
		CHT = {}
		traced_symbol = []
		#mul_count = 0
		mul_list = []
		for node in self.inherTree.nodes(data=True):
			#print node[0],node[1]
			function_list = node[1]["function_list"]
			if "symbol" in node[1]:
				name = node[1]["symbol"]
				if name not in traced_symbol:
					traced_symbol.append(name)
				else:
					'''
					dtor1 = self.vftable_list[CHT[name]["addr"]]["dtor"]
					dtor2 = self.vftable_list[node[0]]["dtor"]

					if (dtor1 != 0) and (dtor1 == dtor2):
					
					print "find not combine vftable:"+name
					print "CHT:%s" % CHT[name]["addr"]
					print node[0],node[1]
					mul_count += 1
					'''
					mul_list.append((CHT[name]["addr"],node[0]))
			else:
				name = node[0]
			CHT[name] = {}
			CHT[name]["base"] = []
			CHT[name]["addr"] = node[0]
			CHT[name]["function_list"] = function_list
			if "dtor" in node[1]:
				CHT[name]["dtor"] = 1
			successors = self.inherTree.successors(node[0])
			for successor in successors:
				if "object_member" in self.inherTree.edges[(node[0],successor)]:
					if "object_member" in CHT[name]:
						if "symbol" in self.inherTree.nodes[successor]:
							CHT[name]["object_member"].append(self.inherTree.nodes[successor]["symbol"])
						else:
							CHT[name]["object_member"].append(successor)
					else:
						CHT[name]["object_member"] = []
						if "symbol" in self.inherTree.nodes[successor]:
							CHT[name]["object_member"].append(self.inherTree.nodes[successor]["symbol"])
						else:
							CHT[name]["object_member"].append(successor)
				else:
					if "symbol" in self.inherTree.nodes[successor]:
						CHT[name]["base"].append(self.inherTree.nodes[successor]["symbol"])
					else:
						CHT[name]["base"].append(successor)

					if "virtual_inherit" in self.inherTree.edges[(node[0],successor)]:
						if "virtual_inherit" in CHT[name]:
							if "symbol" in self.inherTree.nodes[successor]:
								CHT[name]["virtual_inherit"].append(self.inherTree.nodes[successor]["symbol"])
							else:
								CHT[name]["virtual_inherit"].append(successor)
						else:
							CHT[name]["virtual_inherit"] = []
							if "symbol" in self.inherTree.nodes[successor]:
								CHT[name]["virtual_inherit"].append(self.inherTree.nodes[successor]["symbol"])
							else:
								CHT[name]["virtual_inherit"].append(successor)
		# 下面是包含虚继承的处理，可能存在bug导致程序崩溃（盲猜递归达到最大值）
		'''
		virtual_inher_list = []
		for name in CHT:
			if "virtual_inherit" not in CHT[name]:
				for base in CHT[name]["base"]:
					try:
						self.add_virtual_inher(CHT,base,virtual_inher_list)
					except:
						continue
		if len(virtual_inher_list) != 0:
			CHT[name]["virtual_inherit"] = virtual_inher_list
		'''
		'''
		# 统计可能没合并的vftable
		mul_list_file = open("mul_list.txt","w")
		mul_list_jsonstr = json.dumps(mul_list)  
		mul_list_file.write(mul_list_jsonstr)
		mul_list_file.close()
		'''
		return CHT

	'''
	递归寻找添加虚基类
	
	参数：
		CHT：继承树
		base_name：基类索引
		virtual_inher_list：虚基类列表
	'''
	# TODO :分析的结果可能会导致无限递归
	'''
	Recursively looking for adding virtual base classes
	
	Args:
		CHT: inheritance tree
		base_name: base class index
		virtual_inher_list: virtual base class list	
	'''
	def add_virtual_inher(self,CHT,base_name,virtual_inher_list):
		if "virtual_inherit" in CHT[base_name]:
			for virtual_base in CHT[base_name]["virtual_inherit"]:
				if  virtual_base not in virtual_inher_list:
					virtual_inher_list.append(virtual_base)
			return
		for base in CHT[base_name]["base"]:
			self.add_virtual_inher(CHT,base,virtual_inher_list)

	'''
	继承树合并，并去重
	'''
	'''
	Inheritance tree merge and deduplication
	'''
	def combine(self):
		for ctor in self.ctor_tree:
			for node in self.ctor_tree[ctor]["tree"].nodes(data=True):
				#if (node[0] not in self.inherTree.nodes) or ("vftable_list" not in self.inherTree.nodes[node[0]]):

				pass_flag = False
				
				for tree_node in self.inherTree.nodes(data=True):
					# 检查相同节点，保留边多的
					if("vftable_list" in tree_node[1]) and (node[0] == tree_node[0]):
						node_degree = self.ctor_tree[ctor]["tree"].degree[node[0]]
						tree_node_degree = self.inherTree.degree[tree_node[0]]
						# 哪个节点的边多保留哪个节点
						if node_degree <= tree_node_degree:
							pass_flag = True
							break

					# 检查某节点在其他节点vftable列表内
					if ("vftable_list" in tree_node[1]) and (len(tree_node[1]["vftable_list"]) > 1) and (node[0] in tree_node[1]["vftable_list"]):
						pass_flag = True
						break
					
				if pass_flag:
					continue
				

				vftable_list = node[1]["vftable_list"]
				function_list = []
				for vftable in vftable_list:
					function_list.extend(self.vftable_list[vftable]["functions"])					
				
				if "dtor" in self.ctor_list[ctor]:
					# 将符号加入
					if "symbol" in self.vftable_list[node[0]]:
						class_name = self.vftable_list[node[0]]["symbol"]
						self.inherTree.add_node(node[0],vftable_list=vftable_list,function_list=function_list,dtor=1,symbol=class_name)
					else:
						self.inherTree.add_node(node[0],vftable_list=vftable_list,function_list=function_list,dtor=1)
				else:
					# 将符号加入
					if "symbol" in self.vftable_list[node[0]]:
						class_name = self.vftable_list[node[0]]["symbol"]
						self.inherTree.add_node(node[0],vftable_list=vftable_list,function_list=function_list,symbol=class_name)
					else:
						self.inherTree.add_node(node[0],vftable_list=vftable_list,function_list=function_list)
				successors = self.ctor_tree[ctor]["tree"].successors(node[0])
				for successor in successors:
					edge_attr = self.ctor_tree[ctor]["tree"].edges[(node[0],successor)]
					self.inherTree.add_edges_from([(node[0],successor,edge_attr)])
					
					#self.inherTree.edges[(node[0],successor)] = edge_attr
		# 删除节点（该节点在其他节点的vftable列表中）
		del_list = []	
		for node1 in self.inherTree.nodes(data=True):
			for node2 in self.inherTree.nodes(data=True):
				if "vftable_list" not in node2[1]:
					if node2[0] not in del_list:
						del_list.append(node2[0])
				elif (node1[0] != node2[0]) and (len(node2[1]["vftable_list"]) > 1) and (node1[0] in node2[1]["vftable_list"]):
					if node1[0] not in del_list:
						del_list.append(node1[0])
		for node in del_list:
			self.inherTree.remove_node(node)
