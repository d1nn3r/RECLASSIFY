#!/usr/bin/env python
#-*-coding:utf-8-*-
'''
Author:d1nn3r
'''
import idautils
import idaapi
import idc

PLUGIN_VERSION = "1.0.0"
IDAVERISONS = "IDA PRO 7.0+"
AUTHORS     = "d1nn3r"
DATE           = "2020"

 
def banner():
    banner_options = (PLUGIN_VERSION, AUTHORS, DATE, IDAVERISONS)
    banner_titles = "RECLASSIFY v%s - (c) %s - %s - %s" % banner_options
 
# print plugin banner
    print("---[" + banner_titles + "]---\n")
    print("  The hotkeys are Ctrl+R: recover with RTTI, Ctrl+W: recover without RTTI, Ctrl+U: open UML Editor\n")
 
banner()

class NoRttiHandler(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def activate(self, ctx):
		g = globals()
		idahome = idaapi.idadir("python\\RECLASSIFY")
		idaapi.IDAPython_ExecScript(idahome + "\\analyzer.py", g)

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

class RttiHandler(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)


	def activate(self, ctx):
		g = globals()
		idahome = idaapi.idadir("python\\RECLASSIFY")
		idaapi.IDAPython_ExecScript(idahome + "\\analyzerWithRtti.py", g)

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

class UMLEditorHandler(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)


	def activate(self, ctx):
		import webbrowser
		idahome = idaapi.idadir("python\\RECLASSIFY\\UML Editor")
		UMLPath = idahome + "\\index.html"
		webbrowser.open_new_tab(UMLPath)

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS


class RECLASSIFY(idaapi.plugin_t):	

	#flags = idaapi.PLUGIN_UNL
	#flags = idaapi.PLUGIN_FIX
	flags = idaapi.PLUGIN_KEEP
	comment = "Recovering class information from binary."

	wanted_name = "RECLASSIFY"	
	wanted_hotkey = ""  
	help = ""

	def __init__(self):
		super(RECLASSIFY,self).__init__()
		self._data = None

	def NoRtti_menuAction(self):
		action_desc = idaapi.action_desc_t(
			'NoRttiAction',  # The action name. This acts like an ID and must be unique
			'RECLASSIFYWithoutRtti',  # The action text.
			NoRttiHandler(),  # The action handler.
			'Ctrl+W',  # Optional: the action shortcut DO IT  HERE!
			'RECLASSIFYWithoutRtti'#,  # Optional: the action tooltip (available in menus/toolbar)
			#122 #idaapi.load_custom_icon(":/ico/python.png")  # hackish load action icon , if no custom icon use number from 1-150 from internal ida
		)
		# 3) Register the action
		idaapi.register_action(action_desc)
		idaapi.attach_action_to_menu(
			'Edit/RECLASSIFY/',  # The relative path of where to add the action
			'NoRttiAction',  # The action ID (see above)
			idaapi.SETMENU_APP)  # We want to append the action after the 'Manual instruction...


	def Rtti_menuAction(self):
		action_desc = idaapi.action_desc_t(
			'RttiAction',  # The action name. This acts like an ID and must be unique
			'RECLASSIFYWithtRtti',  # The action text.
			RttiHandler(),  # The action handler.
			'Ctrl+R',  # Optional: the action shortcut DO IT  HERE!
			'RECLASSIFYWithRtti'#,  # Optional: the action tooltip (available in menus/toolbar)
			#122 #idaapi.load_custom_icon(":/ico/python.png")  # hackish load action icon , if no custom icon use number from 1-150 from internal ida
		)

		# 3) Register the action
		idaapi.register_action(action_desc)

		idaapi.attach_action_to_menu(
			'Edit/RECLASSIFY/',  # The relative path of where to add the action
			'RttiAction',  # The action ID (see above)
			idaapi.SETMENU_APP)  # We want to append the action after the 'Manual instruction...


	
	def UMLEditor_menuAction(self):
		action_desc = idaapi.action_desc_t(
			'UMLEditorAction',  # The action name. This acts like an ID and must be unique
			'UMLEditor',  # The action text.
			UMLEditorHandler(),  # The action handler.
			'Ctrl+U',  # Optional: the action shortcut DO IT  HERE!
			'UMLEditor'#,  # Optional: the action tooltip (available in menus/toolbar)
			#122 #idaapi.load_custom_icon(":/ico/python.png")  # hackish load action icon , if no custom icon use number from 1-150 from internal ida
		)

		# 3) Register the action
		idaapi.register_action(action_desc)

		idaapi.attach_action_to_menu(
			'Edit/RECLASSIFY/',  # The relative path of where to add the action
			'UMLEditorAction',  # The action ID (see above)
			idaapi.SETMENU_APP)  # We want to append the action after the 'Manual instruction...


	def init(self): 

		try:
			self._install_plugin()
			idaapi.msg("RECLASSIFY load complete.\n")

		# failed to initialize or integrate the plugin, log and skip loading
		except Exception as e:
			form = idaapi.get_current_tform()
			print e


		return idaapi.PLUGIN_KEEP

	def _install_plugin(self):
		self.Rtti_menuAction()
		self.NoRtti_menuAction()
		self.UMLEditor_menuAction()
	
	def run(self, arg):
		pass
	
	def term(self):
		pass


def PLUGIN_ENTRY():
	return RECLASSIFY()