#!/usr/bin/env python
#-*-coding:utf-8-*-
'''
Author:d1nn3r
'''
import json
import angr
import sys
import getopt
import time
import idc
import InforExtraction
import cfg
import StaticTaintAnalysis
import HeuristicReasoning

def usage():
	print "RECLASSIFY usage:"
	print "-f/--file [binary_path] : the analyzed binary's path"
vftable_list = None
vbtable_list = None
ctor_list = None

syscall_count = 0

'''
打印基本块详细信息

参数：
	graph：CFG
	addr：基本块地址
	blocks：已打印的基本块列表
'''
'''
Print basic block details

Args:
	graph: CFG
	addr: basic block address
	blocks: List of printed basic blocks
'''
def print_block(graph,addr,blocks):
	global syscall_count
	if addr in blocks:
		return
	graph.nodes[addr]["block"].pp()
	if "syscall" in graph.nodes[addr]:
		print graph.nodes[addr]["syscall"]
		syscall_count += 1
	if "loop" in graph.nodes[addr]:
		print "loop"
	if "noreturn" in graph.nodes[addr]:
		print "noreturn:"+hex(graph.nodes[addr]["noreturn"]).strip("L")
	successors = list(graph.successors(addr))
	print "successors:"
	for successor in successors:
		print hex(successor)
	print "predecessors:"
	predecessors = list(graph.predecessors(addr))
	for predecessor in predecessors:
		print hex(predecessor)

	print "\n"
	blocks.append(addr)
	for successor in successors:
		print_block(graph,successor,blocks)

'''
打印CFG，将其重定向到文件中

参数：
	mycfg：CFG
'''
'''
Print CFG and redirect it to a file

Args:
	mycfg: CFG
'''
def print_cfg(mycfg):
	f = open("cfg.txt","w")
	savedStdout = sys.stdout  #保存标准输出流
	sys.stdout = f  #标准输出重定向至文件
	for func in mycfg.functions:
		blocks = []
		print "func_addr: " + func
		print_block(mycfg.functions[func],int(func,16),blocks)
	print syscall_count
	sys.stdout = savedStdout  #恢复标准输出流

'''
打印覆写分析结果详细信息，并将其重定向到文件

参数：
	myoverwrite：覆写分析实例
'''
'''
Print detailed information of overwrite analysis result and redirect it to a file

Args:
	myoverwrite: Overwrite analysis instance
'''
def print_overwrite(myoverwrite):
	f = open("overwrite.txt","w")
	savedStdout = sys.stdout  #保存标准输出流
	sys.stdout = f  #标准输出重定向至文件
	for ctor in myoverwrite.ctor_list:
		print "ctor_function:" + ctor
		print "this_offset:"
		for this_offset in myoverwrite.ctor_list[ctor]["this_offset"]:
			print this_offset,myoverwrite.ctor_list[ctor]["this_offset"][this_offset]
		if "new_addr" in myoverwrite.ctor_list[ctor]:
			print "new_addr:", myoverwrite.ctor_list[ctor]["new_addr"]
		if "dtor" in myoverwrite.ctor_list[ctor]:
			print "dtor"
		if "no_new" in myoverwrite.ctor_list[ctor]:
			print "no_new"
		if "multi_class" in myoverwrite.ctor_list[ctor]:
			print "multi_class"
		if "unknow" in myoverwrite.ctor_list[ctor]:
			print "unknow"
		print "\n"
	sys.stdout = savedStdout  #恢复标准输出流

'''
将继承树的json格式数据保存到文件中

参数：
	inheritance_tree：继承树实例
'''
'''
Save the json format data of the inheritance tree to a file

parameter:
	inheritance_tree: inheritance tree instance
'''
def print_CHT(inheritance_tree):
	#f = open("CHT.txt","w")
	#savedStdout = sys.stdout  #保存标准输出流
	#sys.stdout = f  #标准输出重定向至文件
	CHT = inheritance_tree.gen_json()
	#for class_name in CHT:
	#	print class_name, CHT[class_name]
	'''
	for node in inheritance_tree.inherTree.nodes(data=True):
		if "symbol" in node[1]:
			print "class:" , node[1]["symbol"]
		else:
			print "class:" , node[0]
		print "base:"
		successors = inheritance_tree.inherTree.successors(node[0])
		for successor in successors:
			if "virtual_inherit" in inheritance_tree.inherTree.edges[(node[0],successor)]:
				if "symbol" in inheritance_tree.inherTree.nodes[successor]:
					print inheritance_tree.inherTree.nodes[successor]["symbol"],"virtual_inherit"
				else:
					print successor,"virtual_inherit"
			else:
				if "symbol" in inheritance_tree.inherTree.nodes[successor]:
					print inheritance_tree.inherTree.nodes[successor]["symbol"]
				else:
					print successor
		print "\n"
	'''
	#sys.stdout = savedStdout  #恢复标准输出流

	CHTjson_file = open("NodeTreejson.txt","w")
	CHT_jsonstr = json.dumps(CHT)  
	CHTjson_file.write(CHT_jsonstr)
	CHTjson_file.close()



def main():
	# 命令行模式将下面注释去掉，并将IDA python相关函数加上注释，即InforExtraction单独为IDA脚本，后面的独立IDA外执行，调试模式时有用
	'''
	try:
		options,args = getopt.getopt(sys.argv[1:],"hf:", ["help","file="])
	except getopt.GetoptError:
		sys.exit()
	binary = None
	for name,value in options:
		if name in ("-h","--help"):
			usage()
			sys.exit()
		if name in ("-f","--file"):
			binary = value
	if binary == None:
		usage()
		sys.exit()
	'''
	print "[+]log: Start analysis"
	binary = idc.GetInputFilePath()

	isPIE = idc.GetDisasm(0)
	# 基址从0开始
	if len(isPIE) == 0:
		proj = angr.Project(binary, load_options={'auto_load_libs': False,'extern_size': 0x800000})
	# 基址从非0开始, ELF文件中有的需要手动设定基址为0，否则IDA分析的地址数据与angr分析的地址数据不一致
	else:
		# 在最新版本中：custom_base_addr -> base_addr
		proj = angr.Project(binary, load_options={'main_opts':{'custom_base_addr':0},'auto_load_libs': False,'extern_size': 0x800000})
	
	isPE = proj.loader.all_pe_objects
	if len(isPE) == 0:
		filetype = "ELF"
	else:
		filetype = "PE"

	InforExtraction.main(filetype)	


	vftable_file = open("vftable","r")
	vftable_jsonstr = vftable_file.read()	
	vftable_list = json.loads(vftable_jsonstr) 
	vftable_file.close()

	if filetype == "PE":
		vbtable_file = open("vbtable","r")
		vbtable_jsonstr = vbtable_file.read()	
		vbtable_list = json.loads(vbtable_jsonstr)
		vbtable_file.close()
		VTT_list = None
	elif filetype == "ELF":
		VTT_file = open("VTT","r")
		VTT_jsonstr = VTT_file.read()	
		VTT_list = json.loads(VTT_jsonstr)
		VTT_file.close()
		vbtable_list = None
	ctor_file = open("ctor","r")
	ctor_jsonstr = ctor_file.read()	
	ctor_list = json.loads(ctor_jsonstr)
	ctor_file.close()

	symbol_file = open("symbol","r")
	symbol_jsonstr = symbol_file.read()	
	symbol_list = json.loads(symbol_jsonstr)
	symbol_file.close()

	#print vftable_list
	#print vbtable_list
	#print ctor_list
	
	

	# 生成ctor CFG
	start = time.time()
	start_points = []
	for ctor_addr in ctor_list:
		start_points.append(int(ctor_addr,16))
	for vftable in vftable_list:
		if vftable_list[vftable]["dtor"] != 0:
			start_points.append(int(vftable_list[vftable]["dtor"],16))

	mycfg = cfg.CFG(proj=proj,start_points=start_points,symbol_list=symbol_list,thread_num=1)
	end = time.time()
	print "[+]log: Build ctor cfg completion. Time:%fs" % (end-start) 
	#print_cfg(mycfg)

	print "[*]log: The number of analysis functions:%d" % len(mycfg.functions)

	# 进行覆写分析
	start = time.time()
	myoverwrite = StaticTaintAnalysis.StaticTaintAnalysis(proj,mycfg,vftable_list,vbtable_list,VTT_list,ctor_list,symbol_list,filetype)
	end = time.time()
	print "[+]log: Overwrite analysis completion. Time:%fs" % (end-start)
	#print_overwrite(myoverwrite)
	#sys.exit()
	# 继承树生成
	start = time.time()
	inheritance_tree = HeuristicReasoning.HeuristicReasoning(proj,mycfg,myoverwrite.ctor_list,vftable_list,symbol_list)
	end = time.time()
	print "[+]log: Build inherTree completion. Time:%fs" % (end-start)

	inheritance_tree.statistics()
	#inheritance_tree.draw_ctor()
	print_CHT(inheritance_tree)
	inheritance_tree.draw()
	
	
	

	
	    


if __name__ == "__main__":
	start = time.time()
	main()
	end = time.time()
	print "time:%fs" % (end-start) 
