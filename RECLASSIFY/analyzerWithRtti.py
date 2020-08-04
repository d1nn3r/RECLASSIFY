#!/usr/bin/env python
#-*-coding:utf-8-*-
'''
Author:d1nn3r
'''
import json
import angr
import time
import re
import idautils
import idaapi
import idc
import sys
import struct


vftable_section_names = [".rodata",
	".data.rel.ro",
	".data.rel.ro.local",
	".rdata"]

rtti_list = []

class_list = {}

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
	symbol = ""
	last_add_addr = 0
	
	while cur_addr <= seg_end - 8:                   #32 is 4
		data = idc.Qword(cur_addr)                  #32 is Dword

		hasRtti = 0
		# 寻找他的rtti,第一项有交叉引用，第二项在rodata段，为类名
		rttiptr = idc.Qword(cur_addr)
		if  (rodata_start <= rttiptr < rodata_end) or ((hasdrr == 1) and (drrdata_start <= rttiptr < drrdata_end)) :
			rttixrefs = list(idautils.XrefsTo(rttiptr))
			if len(rttixrefs) != 0:
				nameptr = idc.Qword(rttiptr+8)
				if rodata_start <= nameptr < rodata_end:
					hasRtti = 1
					# rttiptr上一项<=0,下一项为虚函数或者为0
					if (struct.unpack('q',struct.pack('Q',idc.Qword(cur_addr-8)))[0]<=0) and ((text_start <= idc.Qword(cur_addr+8) < text_end) or (idc.Qword(cur_addr+8) == 0)):
						rtti_addr = idc.Qword(cur_addr)
						if rtti_addr not in rtti_list:
							symbol = idc.GetOpnd(cur_addr,0)
							symbol = re.sub(r'^offset ','',symbol)
							class_list[symbol] = dict()
							class_list[symbol]["addr"] = rtti_addr
							class_list[symbol]["base"] = list()

							class_list[symbol]["function_list"] = list()

							rtti_list.append(rtti_addr)
		# 若找到rttiptr，添加的函数为0（只有前两项），函数在代码段上，函数在extern段中
		if len(symbol) != 0:
			if ((data==0) and (len(class_list[symbol]["function_list"])<2)) or (text_start <= data < text_end) or (extern_start <= data < extern_end):
				class_list[symbol]["function_list"].append(hex(data).strip("L"))
			else:
				symbol == ""

		cur_addr += 8  

'''
GCC：建立类层次结构

1.RTTI第四项记录着直接基类的数量，后面每两个字段为一个基类组
2.对于每个基类组，第一项为RTTI ptr，第二项为该基类的属性，若属性值<0则该基类为虚基类
'''
'''
GCC: Building a class hierarchy

1. The fourth item of RTTI records the number of direct base classes, and every two fields behind are a base class group
2. For each base class group, the first item is RTTI ptr, and the second item is the attribute of the base class. If the attribute value is <0, the base class is a virtual base class
'''
def build_gcc():
	for item in class_list:
		attribute = idc.Dword(class_list[item]["addr"]+0x10)
		num = idc.Dword(class_list[item]["addr"]+0x14)
		if (0<= attribute <= 4) and (0<num < 100):
			i = 0
			while i < num:
				symbol = idc.GetOpnd(class_list[item]["addr"]+0x18+i*0x10,0)
				symbol = re.sub(r'^offset ','',symbol)
				class_list[item]["base"].append(symbol)
				virtual_attri = idc.Qword(class_list[item]["addr"]+0x18+i*0x10+8)

				if struct.unpack('q',struct.pack('Q',virtual_attri))[0] < 0:
					if "virtual_inherit" in class_list[item]:
						class_list[item]["virtual_inherit"].append(symbol)
					else:
						class_list[item]["virtual_inherit"] = list()
						class_list[item]["virtual_inherit"].append(symbol)
				i += 1
		else:
			symbol = idc.GetOpnd(class_list[item]["addr"]+0x10,0)
			symbol = re.sub(r'^offset ','',symbol)
			addr = idc.Qword(class_list[item]["addr"]+0x10)
			# 排除类定义到其他文件的  extern
			if (symbol[:4] == "_ZTI") and ((addr < extern_start ) or (addr > extern_end)):
				class_list[item]["base"].append(symbol)



def rtti_gcc():
	search_vftable_list_gcc()
	build_gcc()

'''
MSVC:寻找vftable, 将其加入vftable_list中

1.data在代码段
2.vftable第一项有交叉引用同时前一项有RTTI；否则将其加入vftable函数列表中

参数： 
	seg： 段起始地址

'''
''' 
MSVC: Search vftable, and add it into vftable_list

1.data is in .text
2. The first item of vftable has cross reference and the previous item has RTTI; otherwise, add it to the list of vftable functions

Args:
	seg: segment address

'''
def find_vftable_msvc(seg):
	seg_start = idc.SegStart(seg)
	seg_end = idc.SegEnd(seg)
	cur_addr = seg
	symbol = ""
	
	while cur_addr <= seg_end - 8:                   #32 is 4
		data = idc.Qword(cur_addr)                  #32 is Dword
		# 检测data是否在.text段
		# check if the data in .text
		if text_start <= data < text_end:
			xrefs = list(idautils.XrefsTo(cur_addr))
			rttiptr = idc.Qword(cur_addr-8)
			nameptr = idaapi.get_imagebase() + idc.Dword(rttiptr+0x10)
			
			if (len(xrefs) !=0) and (rdata_start <= rttiptr < rdata_end) and (nameptr not in rtti_list): 
				
				symbol = idc.GetOpnd(rttiptr+0x10,0)
				symbol = re.sub(r'^rva ','',symbol)
				class_hierarchy_addr = nameptr

				class_list[symbol] = dict()
				class_list[symbol]["addr"] = class_hierarchy_addr
				class_list[symbol]["base"] = list()
				class_list[symbol]["function_list"] = [hex(data).strip("L")]

				rtti_list.append(nameptr)

			elif symbol != "":      
				class_list[symbol]["function_list"].append(hex(data).strip("L"))
				
		cur_addr += 8                                #32 is 4

def search_vftable_list_msvc():
	for seg in idautils.Segments():
		if idc.SegName(seg) in vftable_section_names:
			find_vftable_msvc(seg)

def build_msvc():
	for item in class_list:
		hierarchy_build(item,0)

'''
MSVC：递归建立类层次结构

1.检查RTTI Class Hierarchy Descriptor第三个字段，若大于1则存在基类，并进入第四个字段基类数组的地址
	+0  unsigned long       signature;       // 似乎都是 0
	+4  unsigned long       attributes;      // 第0位置1表示多继承，
	                                         // 第1位置1表示虚继承
	+8  unsigned long       numBaseClasses;  // 基类数量，包括自己在内，所以数量加1
	+c  RTTIBaseClassArray* pBaseClassArray; // 基类的数组

2.除第一个是自己以外，遍历基类数组构建类层次结构，基类数组是以深度优先排列类顺序的

3.RTTI Base Class Descriptor第四个字段若大于0则为虚基类
	+0  TypeDescriptor *pTypeDescriptor; // 基类自身的信息
	+4  unsigned long numContainedBases; // 基类的父类数量
	+8  PMD where;
	    +0  unsigned long mdisp;         // 成员偏移
	    +4  unsigned long pdisp;         // 虚基类表在类中的偏移，
	                                     // 如果是 -1 说明该类不是其虚基类
	    +8  unsigned long vdisp;         // 基类在虚基类表中的偏移
	+14 unsigned long attributes;        // 
	+18 RTTIClassHierarchyDescriptor* pClassDescriptor; // 基类的继承信息

参数：
	item：类名
	hierarchy：递归次数，代表函数层级

返回：
	traced_base_list：遍历过的基类列表，list
'''
'''
MSVC: Recursively build class hierarchy

1. Check the third field of RTTI Class Hierarchy Descriptor, if it is greater than 1, there is a base class, and enter the address of the fourth field base class array
	+0 unsigned long signature; // all seem to be 0
	+4 unsigned long attributes; // The 0th position 1 means multiple inheritance,
	// The first position 1 indicates virtual inheritance
	+8 unsigned long numBaseClasses; // The number of base classes, including themselves, so the number is increased by 1
	+c RTTIBaseClassArray* pBaseClassArray; // array of base class

2. Except for the first one is self, traverse the base class array to build the class hierarchy. The base class array is sorted in depth first

3. If the fourth field of RTTI Base Class Descriptor is greater than 0, it is a virtual base class
	+0 TypeDescriptor *pTypeDescriptor; // Information of the base class itself
	+4 unsigned long numContainedBases; // The number of parent classes of the base class
	+8 PMD where;
	+0 unsigned long mdisp; // member offset
	+4 unsigned long pdisp; // The offset of the virtual base class table in the class,
	// If it is -1, the class is not its virtual base class
	+8 unsigned long vdisp; // Offset of the base class in the virtual base class table
	+14 unsigned long attributes; //
	+18 RTTIClassHierarchyDescriptor* pClassDescriptor; // inheritance information of the base class

Args:
	item: class name
	hierarchy: Recursion times, representing function hierarchy

Return:
	traced_base_list: traversed base class list, list
'''
# TODO:有时复杂的文件会出现无限循环还没有找到原因
def hierarchy_build(item,hierarchy):
	traced_base_list = []
	# 防止无限循环
	if hierarchy > 20:
		return traced_base_list
	else:
		this_hierarchy = hierarchy 
		this_hierarchy += 1
	try:
		base_num = idc.Dword(class_list[item]["addr"]+8)
	except:
		return traced_base_list
	if base_num > 1:
		base_list_ptr = idaapi.get_imagebase() + idc.Dword(class_list[item]["addr"]+0xC)		
		i = 1 
		while i < base_num:
			base_desc_ptr = idaapi.get_imagebase() + idc.Dword(base_list_ptr+i*4)
			symbol = idc.GetOpnd(base_desc_ptr+0x18,0)
			symbol = re.sub(r'^rva ','',symbol)
			if (symbol not in traced_base_list) and (symbol != item):
				if symbol not in class_list[item]["base"]:
					class_list[item]["base"].append(symbol)

				if struct.unpack('l',struct.pack('L',idc.Dword(base_desc_ptr+0xC)))[0] > 0:
					if "virtual_inherit" in class_list[item]:
						if symbol not in class_list[item]["virtual_inherit"]:
							class_list[item]["virtual_inherit"].append(symbol)
					else:
						class_list[item]["virtual_inherit"] = list()
						class_list[item]["virtual_inherit"].append(symbol)

				traced_base_list.append(symbol)				
				traced_base_list.extend(hierarchy_build(symbol,this_hierarchy))

			i += 1
	return traced_base_list



def rtti_msvc():
	search_vftable_list_msvc()
	build_msvc()


'''
对结果进行统计，并将结果保存到result文件中
'''
'''
Count the results and save the results to the "result" file
'''
def statistics():
	class_count = 0
	no_inher = 0
	single_inher = 0
	multi_inher = 0
	virtual_inher = 0

	for item in class_list:
		class_count += 1
		inher_count = len(class_list[item]["base"])
		if inher_count == 0:
			no_inher += 1
		elif inher_count == 1:
			single_inher += 1
		elif inher_count > 1:
			multi_inher += 1
		if "virtual_inherit" in class_list[item]:
			virtual_inher += len(class_list[item]["virtual_inherit"])
			
	print "Analysis result:"
	print "class_num:"+str(class_count)
	print "no_inher:"+str(no_inher)
	print "single_inher:"+str(single_inher)
	print "multi_inher:"+str(multi_inher)
	print "virtual_inher:"+str(virtual_inher)


	result_file = open("result","w")
	result_file.write("class_num:"+str(class_count)+"\n")
	result_file.write("no_inher:"+str(no_inher)+"\n")
	result_file.write("single_inher:"+str(single_inher)+"\n")
	result_file.write("multi_inher:"+str(multi_inher)+"\n")
	result_file.write("virtual_inher:"+str(virtual_inher)+"\n")
	result_file.close()




'''
对整个继承树进行绘图，生成.gv和.pdf文件
'''
'''
Draw the entire inheritance tree and generate .gv and .pdf files
'''
def draw():
	from graphviz import Digraph
	nodetree = Digraph('NodeTree', node_attr={'shape': 'plaintext'})
	nodetree.attr(rankdir="BT")
	for node in class_list:
		function_list = class_list[node]["function_list"]
		name = node

		label = '<<TABLE BORDER="0" CELLBORDER="1" CELLPADDING="5" CELLSPACING="0"><TR><TD><B>'
		label += name
		label += '</B></TD></TR><TR><TD ALIGN="LEFT" BALIGN="LEFT" >'
		label += '</TD></TR><TR><TD ALIGN="LEFT" BALIGN="LEFT" >'
		i = 0
		for function_addr in function_list:
			if i!=0:
				label += "<BR/>"
			label += function_addr
			i += 1
		label += '</TD></TR></TABLE>>'

		nodetree.node(node,label)

		if "virtual_inherit" in class_list[node]:
			for base in class_list[node]["virtual_inherit"]:
				nodetree.edge(node,base,"virtual_inherit",arrowhead='onormal')

		for base in class_list[node]["base"]:
			if "virtual_inherit" in class_list[node]:
				if base not in class_list[node]["virtual_inherit"]:
					nodetree.edge(node,base,arrowhead='onormal')
			else:
				nodetree.edge(node,base,arrowhead='onormal')

		

	nodetree.save()
	nodetree.render()
	#nodetree.view()
	print "[+]log: Draw completion"

def main():
	
	binary = idc.GetInputFilePath()
	proj = angr.Project(binary, load_options={'auto_load_libs': False,'extern_size': 0x800000})
	
	isPE = proj.loader.all_pe_objects
	if len(isPE) == 0:
		filetype = "ELF"
	else:
		filetype = "PE"

	if filetype == "ELF":
		rtti_gcc()
	elif filetype == "PE":
		rtti_msvc()
	
	

	#for item in class_list:
	#	class_list[item]["addr"] = hex(class_list[item]["addr"]).strip("L")
	#	print item,class_list[item]
	#print "count:%d" % len(class_list)

	src_list_file = open('NodeTreejson.txt', 'w')
	src_list_jsonstr = json.dumps(class_list) 
	src_list_file.write(src_list_jsonstr)
	src_list_file.close()
	
	statistics()
	draw()
	    


if __name__ == "__main__":
	start = time.time()
	main()
	end = time.time()
	print "time:%fs" % (end-start) 
