#!/usr/bin/env python
#-*-coding:utf-8-*-
'''
Author:d1nn3r
'''
import networkx
import angr
import pyvex
import Queue
import threading
import sys

'''
对指定函数及其相关函数生成CFG

成员变量：
	start_points：需要分析的函数地址
	proj：angr程序实例
	cg_graph：函数调用图
	functions：函数CFG列表，list
		数据格式：
			func_addr：函数地址，newworkx.DiGraph
				block：基本块，angr的irsb
				syscall:包含的系统函数符号，若不存在则该项不存在
				loop：若存在循环结构则为1，否则该项不存在
				noreturn：若存在noreturn结构则为1，否则该项不存在
	thread_num：分析需要的线程，默认为10
	resolved_block: 已分析的基本块
	symbol_list: 系统符号表
	is_one: 为单一函数生成CFG，默认为False
	target_block_addr: is_one为True时，为待生成的CFG的函数地址,默认为None
	jobs：待生成CFG的函数队列
'''
'''
Generate CFG for specified functions and related functions

Memebers:
	start_points: address of the function to be analyzed
	proj: angr program instance
	cg_graph: function call graph
	functions: CFG list of functions
		Data Format:
			func_addr: function address, newworkx.DiGraph
				block: basic block, irsb of angr
				syscall: Contains the system function symbol, if it does not exist, the item does not exist
				loop: 1 if there is a loop structure, otherwise the item does not exist
				noreturn: 1 if noreturn structure exists, otherwise the item does not exist
	thread_num: thread for analysis, default is 10
	resolved_block: analyzed basic block
	symbol_list: System symbol table
	is_one: Generate CFG for a single function, default is False
	target_block_addr: when is_one is True, it is the function address of the CFG to be generated, the default is None
	jobs: Function queue to be generated CFG
'''
class CFG:
	def __init__(self,proj,start_points,symbol_list,thread_num=10,is_one=False,target_block_addr=None):
		self.start_points = start_points
		self.proj = proj
		self.cg_graph = networkx.DiGraph()
		self.functions = {}
		self.thread_num = thread_num
		self.resolved_block = None
		self.symbol_list = symbol_list
		self.is_one = is_one
		self.target_block_addr = target_block_addr
		#self.lock = threading.RLock()

		self.jobs = Queue.Queue()
		for j in self.start_points:
			self.jobs.put(j)
			
		#self.analysis()
		self.process_jobs()

	def analysis(self):
		workers = []
		for i in range(self.thread_num):
			workers.append(threading.Thread(target=self.process_jobs))

		for w in workers:
			w.setDaemon(True)
			w.start()
		self.jobs.join()

	def process_jobs(self):
		
		while not self.jobs.empty():
			#self.lock.acquire()
			job = self.jobs.get()
			
			self.process_job(job)

			#self.jobs.task_done()
			#self.lock.release()

	def process_job(self,job):
		# 已经分析过的函数不再分析
		if hex(job).strip("L") in self.functions:
			return
		else:
			self.functions[hex(job).strip("L")] = networkx.DiGraph()
		if self.is_one:
			block = self.proj.factory.block(self.target_block_addr)
		else:
			block = self.proj.factory.block(job)
		self.resolved_block = []
		self.build_cfg(block,self.functions[hex(job).strip("L")])
		self.post_handle(self.functions[hex(job).strip("L")])
	'''
	递归分析每一个基本块

	基本块划分：条件跳转，无条件跳转，函数调用

	参数：
		block: 基本块地址
		cfg：函数CFG
	'''
	'''
	Recursively analyze each basic block

	Basic block division: conditional jump, unconditional jump, function call

	Args:
		block: basic block address
		cfg: function CFG
	'''
	def build_cfg(self,block,cfg):
		cfg.add_node(block.addr,block=block)
		self.resolved_block.append((block.addr,block.addr+block.size))
		irsb = block.vex
	
		#print hex(block.addr)
		#if block.addr > 0x1000000:
		#	sys.exit()

		# angr bug:不能解析一些指令，如jrcxz等
		# 遍历指令寻找中间是否存在pyvex.stmt.Exit类型的指令，若存在则进行分块处理
		last_num = len(block.capstone.insns)-1
		for i,insn in enumerate(block.capstone.insns):
			if (insn.insn.insn_name() == "jrcxz") and (i != last_num):
				size = insn.insn.address-block.addr+insn.insn.size
				new_block = self.proj.factory.block(block.addr,size=size)
				self.build_cfg(new_block,cfg)

				next_addr = block.capstone.insns[i+1].insn.address
				next_block = self.proj.factory.block(next_addr)
				cfg.add_edge(block.addr,next_addr)
				self.build_cfg(next_block,cfg)
				return



		if irsb.jumpkind == "Ijk_Ret":
			return
		elif irsb.jumpkind == "Ijk_Boring":
			stmt = irsb.statements[-1]
			# 条件跳转
			if isinstance(stmt,pyvex.IRStmt.Exit):
				dst_addr = stmt.dst.value
				# 检测循环
				dst_split_addr = 0
				dst_self_addr = 0
				if dst_addr not in cfg:  
					loop,self_addr,split_addr = self.check_loop(cfg,dst_addr)
					if not loop:
						dst_block = self.proj.factory.block(dst_addr)
						cfg.add_edge(block.addr,dst_addr)
						self.build_cfg(dst_block,cfg)
					else:

						dst_self_addr = self_addr
						dst_split_addr = split_addr
						# 如果分割的是自己
						if self_addr == block.addr:
							cfg.add_edge(split_addr,dst_addr)
						else:
							cfg.add_edge(block.addr,dst_addr)
				else:
					cfg.add_edge(block.addr,dst_addr)

				
				next_expr = irsb.next
				# 直接跳转
				if isinstance(next_expr,pyvex.expr.Const):
					next_addr = next_expr.con.value
					if next_addr not in cfg:

						loop,self_addr,split_addr = self.check_loop(cfg,next_addr)

						if not loop:
							# 如果dst是自己
							if dst_self_addr == block.addr:
								cfg.add_edge(dst_split_addr,next_addr)
							else:
								cfg.add_edge(block.addr,next_addr)
							next_block = self.proj.factory.block(next_addr)							
							self.build_cfg(next_block,cfg)
						else:
							
							# 如果分割的是自己
							if self_addr == block.addr:
								cfg.nodes[split_addr]["loop"] = 1
								cfg.add_edge(split_addr,next_addr)
							else:
								cfg.nodes[block.addr]["loop"] = 1
								cfg.add_edge(block.addr,next_addr)
					else:
						# 如果dst是自己
						if dst_self_addr == block.addr:
							cfg.add_edge(dst_split_addr,next_addr)
						else:
							cfg.add_edge(block.addr,next_addr)	

				# TODO: 不知道有没有这种情况，待检测
				# 间接跳转
				else:
					print "[*]error:build_cfg()->next_expr"
					print type(next_expr)
					sys.exit()


				'''
				elif isinstance(next_expr,pyvex.expr.RdTmp):
					tmp = next_expr.tmp
					next_addr,symbol = self.indirect_jumps_handle(irsb,tmp)
					if next_addr != None:
						if next_addr not in cfg:
							loop,self_addr,split_addr = self.check_loop(cfg,next_addr)
							if not loop:
								next_block = self.proj.factory.block(next_addr)
								cfg.add_edge(block.addr,next_addr)
								self.build_cfg(next_block,cfg)
							else:
								# 如果分割的是自己
								if self_addr == block.addr:
									cfg.add_edge(split_addr,next_addr)
								else:
									cfg.add_edge(block.addr,next_addr)
						else:
							cfg.add_edge(block.addr,next_addr)
				'''

			# 无条件跳转 jmp
			elif isinstance(stmt,pyvex.IRStmt.IMark):
				next_expr = irsb.next


				# 直接跳转
				if isinstance(next_expr,pyvex.expr.Const):
					next_addr = next_expr.con.value
					
					# 处理GCC下通过plt表的调用
					if self.proj.loader.find_section_containing(next_addr).name == ".plt":
						jmp_block = self.proj.factory.block(next_addr)
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
									next_addr = bv.args[0]

					#print hex(next_addr)

					# GCC下判断系统调用
					next_addr_str = hex(next_addr).strip("L").lower()
					if next_addr_str in self.symbol_list:
						symbol = self.symbol_list[next_addr_str]
						cfg.nodes[block.addr]["syscall"] = symbol
						return
					elif next_addr > (self.proj.loader.main_bin.mapped_base + self.proj.loader.main_bin.max_addr):
						symbol = "syscall"
						cfg.nodes[block.addr]["syscall"] = symbol
						return

					# angrBUG: 跳转地址识别错误libz3.so
					'''
					if irsb.addr == 0x206362:
						next_addr = 0x205F10
					'''
					# 循环检测
					if next_addr in cfg:
						cfg.add_edge(block.addr,next_addr)
						return
					
					next_block = self.proj.factory.block(next_addr)

					cfg.add_edge(block.addr,next_addr)
					self.build_cfg(next_block,cfg)
				# 间接跳转
				elif isinstance(next_expr,pyvex.expr.RdTmp):
					tmp = next_expr.tmp
					#try:
					next_addr,symbol = self.indirect_jumps_handle(irsb,tmp)
					#except Exception as e:
					#	print e
					#	print block.pp()
					#	print irsb.pp()
					#	print next_addr
					#	print symbol
					#	sys.exit()
					if symbol != None:
						cfg.nodes[block.addr]["syscall"] = symbol
					elif next_addr != 0:
						next_block = self.proj.factory.block(next_addr)
						cfg.add_edge(block.addr,next_addr)
						self.build_cfg(next_block,cfg)
			# angr貌似irsb最大是331条，太大的基本块会被强制截断
			else:
				# 忽略间接调用
				if isinstance(irsb.next,pyvex.expr.Const):
					# MpEngine.dll 0x75A591CA1    rep stosw -> angr bug ：irsb就这一条指令且next还是自己
					if (len(block.capstone.insns) == 1) and (irsb.next.con.value == block.addr):
						insn = block.capstone.insns[-1]
						next_addr = insn.address + insn.size
						next_block = self.proj.factory.block(next_addr)
						cfg.add_edge(block.addr,next_addr)
						self.build_cfg(next_block,cfg)
					else:
						next_addr = irsb.next.con.value
						next_block = self.proj.factory.block(next_addr)
						cfg.add_edge(block.addr,next_addr)
						self.build_cfg(next_block,cfg)

					

				
			
		# TODO:如何识别系统调用 Solved
		elif irsb.jumpkind == "Ijk_Call":
			#try:
			stmt = irsb.statements[-1]
			
			next_expr = irsb.next
			
			syscall = 0
			# 直接调用
			if isinstance(next_expr,pyvex.expr.Const):
				func_addr = next_expr.con.value
				# 处理GCC下通过plt表的调用
				if self.proj.loader.find_section_containing(func_addr).name == ".plt":
					jmp_block = self.proj.factory.block(func_addr)
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
								func_addr = bv.args[0]

				# GCC下判断系统调用
				func_addr_str = hex(func_addr).strip("L").lower()
				if func_addr_str in self.symbol_list:
					symbol = self.symbol_list[func_addr_str]
				elif func_addr > (self.proj.loader.main_bin.mapped_base + self.proj.loader.main_bin.max_addr):
					symbol = "syscall"
				else:
					symbol = self.is_syscall_thunk(func_addr)
				if symbol == None:
					self.jobs.put(func_addr)
				# 若是系统调用的thunk函数则不用添加
				else:
					syscall = 1
					cfg.nodes[block.addr]["syscall"] = symbol
				
			# 间接调用 如call rax,call cs:[0x1000](系统调用)
			elif isinstance(next_expr,pyvex.expr.RdTmp):
				tmp = next_expr.tmp
				func_addr,symbol = self.indirect_jumps_handle(irsb,tmp) 
				if symbol != None:
					cfg.nodes[block.addr]["syscall"] = symbol
				elif func_addr != 0:
					syscall = 1
					self.jobs.put(func_addr)
			
			# 将call指令的下一句指令所在基本块加入cfg
			ins = block.capstone.insns[-1]
			next_addr = ins.insn.address + ins.insn.size
			next_block = self.proj.factory.block(next_addr)
			cfg.add_edge(block.addr,next_addr)
			self.build_cfg(next_block,cfg)

		
			
	'''		
	检测是否是系统调用的thunk

	参数：
		func_addr: 函数地址
	
	返回：
		symbol: 符号名称
	'''
	'''
	Check if it is a thunk called by the system

	Args:
		func_addr: function address

	Return:
		symbol: symbol name
	'''
	def is_syscall_thunk(self,func_addr):
		symbol = None

		block = self.proj.factory.block(func_addr)
		irsb = block.vex
		if (len(irsb.statements) == 2) and (irsb.jumpkind == "Ijk_Boring"):
			next_expr = irsb.next

			if isinstance(next_expr,pyvex.expr.RdTmp):
				tmp = next_expr.tmp
				func_addr,symbol = self.indirect_jumps_handle(irsb,tmp)
		return symbol
	'''
	间接跳转处理

	参数：
		irsb： 基本块
		tmp: 临时变量
		arch： 文件类型，默认64位程序

	返回：
		jump_addr: 跳转地址
		symbol：符号名称
	'''
	'''
	Indirect jump processing

	Args:
		irsb: basic block
		tmp: temporary variable
		arch: file type, default 64-bit program

	Return:
		jump_addr: jump address
		symbol: symbol name
	'''
	def indirect_jumps_handle(self,irsb,tmp,arch=64):
		symbol = None
		jump_addr = 0
		revese_stmts = irsb.statements[::-1]
		for stmt in revese_stmts:	
			if isinstance(stmt,pyvex.stmt.WrTmp) and (stmt.tmp == tmp):
				if isinstance(stmt.data,pyvex.expr.Load):
					expr = stmt.data.child_expressions[0]
					# 系统调用
					if isinstance(expr,pyvex.expr.Const):
						addr = expr.con.value

						addr_str = hex(addr).strip("L").lower()
						# 先从symbol文件中寻找，没找到再使用angr的方法寻找
						if addr_str in self.symbol_list:
							jump_addr = addr
							symbol = self.symbol_list[addr_str]
							#print symbol,self.symbol_list[addr_str]

							return jump_addr,symbol
						else:
							symbol = "syscall"
							return jump_addr,symbol
							'''
							state = self.proj.factory.blank_state()
							if arch == 64:
								bv = state.mem[addr].uint64_t.resolved
							elif arch == 32:
								bv = state.mem[addr].uint32_t.resolved
							#print irsb.pp()
							symbol_addr = bv.args[0]
							try:
								symbol_object = self.proj.loader.extern_object.symbols_by_addr[symbol_addr]
								symbol = symbol_object.demangled_name
								jump_addr = symbol_addr
								return jump_addr,symbol
							# TODO: 处理有些syscal符号没有识别出来的，不在上面那个字典里 可以使用IDA python来提取符号表和地址进行识别
							except Exception as e:
								symbol = "syscall"
								return jump_addr,symbol
							'''

					# TODO:间接跳转处理
					# 其他 
					elif isinstance(expr,pyvex.expr.RdTmp):
						return jump_addr,symbol
				# TODO:间接跳转处理
				else:
					return jump_addr,symbol
	'''
	检测内部循环
	
	参数：
		cfg：函数CFG
		target_addr: 检测的指令地址

	返回：
		loop: 是否有循环结构, 存在循环结构为True，否则为False
		self_addr: 被分解的基本块的上半部分地址
		split_addr： 被分解的基本块的下半部分地址
	'''
	'''
	Detection of internal circulation
	
	Args:
		cfg: function CFG
		target_addr: detected instruction address

	Return:
		loop: whether there is a cyclic structure, the existing cyclic structure is True, otherwise it is False
		self_addr: address of the upper half of the decomposed basic block
		split_addr: the address of the lower half of the split basic block
	'''
	def check_loop(self,cfg,target_addr):
		# 检测如下情况：
		# ———————————
		# |         |
		# |         |←——————
		# |         |      |
		# |         |      |
		# ———————————      |
		#      ↓           |
		# ———————————      |
		# |         |      |
		# |         |      |
		# |         |      |
		# |         |      |
		# ——————————— ——————  
		# 
		# 和
		# ———————————
		# |         |
		# |         |←——————
		# |         |      |
		# |         |      |
		# ——————————— ——————   
		loop = False
		self_addr = 0
		split_addr = 0
		for addr in self.resolved_block:
			if addr[0] < target_addr < addr[1]:
				loop = True
				self_addr = addr[0]
				size = target_addr - addr[0]
				split_addr = target_addr

				# 将基本块分裂
				cfg.nodes[addr[0]]["block"] = self.proj.factory.block(addr[0],size=size)
				split_block = self.proj.factory.block(split_addr)
				cfg.add_node(split_addr,block=split_block)
				self.resolved_block.remove(addr)
				self.resolved_block.append((cfg.nodes[addr[0]]["block"].addr,cfg.nodes[addr[0]]["block"].addr+cfg.nodes[addr[0]]["block"].size))
				self.resolved_block.append((split_block.addr,split_block.addr+split_block.size))
				successors = list(cfg.successors(addr[0]))
				if len(successors) !=0:
					for successor in successors:
						cfg.remove_edge(addr[0],successor)
						cfg.add_edge(split_addr,successor)
					cfg.add_edge(addr[0],split_addr)
				else:
					cfg.add_edge(addr[0],split_addr)
				break
		return loop,self_addr,split_addr

	'''
	建立基本块后处理分析

	1. noreturn处理
	2. 异常处理例程处理
	3. 错误分支处理

	参数：
		cfg: 函数CFG
	'''
	'''
	Post-processing analysis of building basic blocks

	1. noreturn processing
	2. Exception handling routine processing
	3. Error branch handling

	Args:
		cfg: Function CFG
	'''
	def post_handle(self,cfg):
		for item in cfg.nodes.items():
			block = item[1]["block"]
			irsb = block.vex
			# noreturn处理
			if (irsb.jumpkind != "Ijk_Ret") and (irsb.jumpkind != "Ijk_Boring") and (irsb.jumpkind != "Ijk_Call"):
				# noreturn处理 例如int3 -> Ijk_SigTRAP
				self.noreturn_handle(cfg,block.addr)
			if "syscall" in item[1]:
				# 处理所有异常函数的noreturn类型
				if "throw" in item[1]["syscall"].lower():
					self.noreturn_handle(cfg,block.addr)
					# 删除后面的连接节点
					successors = list(cfg.successors(item[0]))
					for successor in successors:
						cfg.remove_edge(item[0],successor)
				if "unwind" in item[1]["syscall"].lower():
					self.noreturn_handle(cfg,block.addr)
					# 删除后面的连接节点
					successors = list(cfg.successors(item[0]))
					for successor in successors:
						cfg.remove_edge(item[0],successor)
			# 有的有三条分支，而实际只有一条或两条
			successors = list(cfg.successors(item[0]))
			next_count = len(successors)
			if len(successors) == 3:
				if block.capstone.insns[-1].insn.insn_name() == "jmp":
					jmp_addr = irsb.next.con.value
					for successor in successors:
						if successor != jmp_addr:
							cfg.remove_edge(item[0],successor)
			# 有的有两条分支，而实际只有一条
			if len(successors) == 2:
				if isinstance(irsb.statements[-1],pyvex.stmt.IMark):
					next_addr = irsb.next.con.value
					for successor in successors:
						if successor != next_addr:
							cfg.remove_edge(item[0],successor)
	'''
	noreturn处理

	noreturn = 1 表示该路径为noreturn路径
	noreturn = block_addr 表示该block的block_addr分支为noreturn

	参数：
		cfg: 函数CFG
		block_addr: 存在noreturn的基本块的地址
	'''
	'''
	noreturn processing

	noreturn = 1 means the path is noreturn
	noreturn = block_addr indicates that the block_addr branch of the block is noreturn

	Args:
		cfg: Function CFG
		block_addr: the address of the basic block with noreturn
	'''
	def noreturn_handle(self,cfg,block_addr):

		if "noreturn" in cfg.nodes[block_addr]:
			return
		cfg.nodes[block_addr]["noreturn"] = 1
		predecessors = list(cfg.predecessors(block_addr))
		for predecessor in predecessors:
			successors = list(cfg.successors(predecessor))
			if len(successors) == 2:
				cfg.nodes[predecessor]["noreturn"] = block_addr
			else:
				self.noreturn_handle(cfg,predecessor)






