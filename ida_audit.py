import idc 
import idautils 
import idaapi
from prettytable import PrettyTable 


arg_reg = [
	'rdi', 
	'rsi', 
	'rdx', 

]


# set function_name
dangerous_functions = [
    "strcpy", 
    "strcat",  
    "sprintf",
    "read", 
    "getenv"    
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf", 
    "strncat", 
    "snprintf",
    "vprintf", 
    "printf"
]

command_execution_function = [
    "system", 
    "execve",
    "popen",
    "unlink"
]


# describe arg num of function
zero_arg_function = (
	"sprintf",
    "sscanf",
    "snprintf",
    "vprintf",
    "printf"
)

one_arg_function = (
    "getenv",
    "system",
    "unlink"
)

two_arg_function = (
    "strcpy", 
    "strcat",
    "popen"
)

three_arg_function = (
    "strncpy",
    "strncat", 
    "memcpy",
    "execve",
    "read"
)



format_function_offset_dict = {
    ".sprintf":1,
    ".sscanf":1,
    ".snprintf":2,
    ".vprintf":0,
    "printf":0
}

arg_num = [
    one_arg_function,
    two_arg_function,
    three_arg_function,
]

def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Aduiting " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

def getFuncAddr(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr != idc.BADADDR:
        print(printFunc(func_name))
        return func_addr
    return False

def find_arg(arg_addr):
	if(idc.get_operand_type(arg_addr, 1) != 1):
		arg = idc.print_operand(arg_addr, 1)
		if "offset" in arg:
			return arg[7:]
		else:
			return arg

	func = idaapi.get_func(arg_addr).start_ea
	line = arg_addr
	return hand_register(arg_addr, idaapi.get_func(arg_addr).start_ea, idc.print_operand(arg_addr, 1))
	

def enum_arg(call_addr):
	idc.set_color(call_addr,CIC_ITEM,0x00ff00)
	arg = []
	for arg_addr in idaapi.get_arg_addrs(call_addr):
		idc.set_cmt(arg_addr, "addr: 0x%x" % (call_addr), 0)
		idc.set_color(arg_addr,CIC_ITEM,0x00fff0)
		arg.append(find_arg(arg_addr))
	return arg

def function_arg_number(func_name):
	for i , function in enumerate(arg_num, 1):
		if func_name in function:
			return i 

def hand_register(current, start_ea, reg_target):
	while(current >= start_ea):
		current = idc.prev_head(current)
		if(idc.print_operand(current, 0) == reg_target):
			return idc.print_operand(current, 1)


def format_args(call_addr, fmt_num):
	func = idaapi.get_func(call_addr)
	start = func.start_ea
	string = ""
	for i in range(1, fmt_num+1):
		line = call_addr
		reg = arg_reg[i]
		while line >= start:
			line = prev_head(line)
			line_arg = idc.print_operand(line, 0)
			if reg == line_arg:
				idc.set_color(line,CIC_ITEM,0x00fff0)
				if(idc.get_operand_type(line, 1) != 1):
					string += ", '%s'" %(idc.print_operand(line, 1))
				else:
					string += ", '%s'" % (hand_register(line, start, idc.print_operand(line, 1)))
				break
	return string


def format_string(call_addr, format_name):
	string = ''
	format_addr = idc.LocByName(format_name)
	if idc.GetStringType(format_addr) == 0:
		fmt_str = idc.GetString(format_addr).decode()
		string = "'%s'" % fmt_str
		fmt_num = fmt_str.count('%')
		if fmt_num > 0:
			string += ", %d" % fmt_num
			string += "%s" % format_args(call_addr, fmt_num)
	else:
		string += "null! A dangerous address, may have a format string vulnerability"
	return [string]

def enum_arg_format(call_addr, index):
	arg = enum_arg(call_addr) 
	return arg + format_string(call_addr, arg[index])

def audit_format_function(func_name, func_addr):
	index = format_function_offset_dict[func_name]
	table_head = [func_name] + ["arg%s" %(i+1) for i in range(index + 1)] + [" format&value[string_addr, num of '%', fmt_arg...]"]
	# print(table_head)
	table = PrettyTable(table_head)
	for call_addr in idautils.CodeRefsTo(func_addr, 0):
		table.add_row([hex(call_addr)] + enum_arg_format(call_addr, index))
	print(table)

def audit(func_name):
	func_addr = getFuncAddr(func_name)
	if func_addr == False:
		return  False

	if idc.SegName(func_addr) == 'extern':
		func_addr = list(idautils.CodeRefsTo(func_addr, 0))[0]

	if func_name in format_function_offset_dict:
		return audit_format_function(func_name, func_addr)
	return audit_function(func_name, func_addr)


def audit_function(func_name, func_addr):
	table_head = [func_name] + ["arg%s" % (i+1)  for i in range(function_arg_number(func_name))]
	table = PrettyTable(table_head)

	for call_addr in idautils.CodeRefsTo(func_addr, 0):
		table.add_row([hex(call_addr)] + enum_arg(call_addr))
	print(table)


def ida_audit():
	start = '''
	'''
	print(start)

	print ("Auditing dangerous functions ......")
	for func_name in dangerous_functions:
		audit(func_name)

	print ("Auditing attention function ......")
	for func_name in attention_function:
		audit(func_name)

	print ("Auditing command execution function ......")
	for func_name in command_execution_function:
		audit(func_name)

	print ("Finished! Enjoy the result ~")

ida_audit()
