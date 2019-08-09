---
layout: post
title: "Monitoring crash on windows for fuzz harness devl."
categories: fuzzing
---

When you are fuzzing on windows, crash monitoring of process is important aspect of your harness implementation. In this post I have tried to list down different methods I've used for monitoring exception of user mode applications on windows.

1. **Using Win32 Apis / Debugger automation**
This is the far most common method used to monitor for fault of user mode program on windows. This work straightforward by attaching debugger to program and monitoring for first-chance/second-chance exception (mostly access-violations) to signal crash to fuzzer. Various debugger automation frameworks written in are available on windows like [WinappDbg](http://winappdbg.sourceforge.net/) / [Pykd](https://pypi.org/project/pykd/) that works out of the box for this purpose, further letting user access program state. Below is sample monitor in python using winappdbg. 

```
import sys
from winappdbg import win32, Debug, HexDump, Crash
def debug_event_handler( event ):
    code = event.get_event_code()
    if code == win32.EXCEPTION_DEBUG_EVENT and event.is_last_chance():
        #TODO: We've process crash notification, report it
        event.get_process().kill()
        
def monitor_for_exception(pid):            
	with Debug(debug_event_handler, bKillOnExit = True) as debug:
    	debug.attach( pid )
    	debug.loop()
```

Winappdbg is my favorite pure python wrapper around windows debugging apis using ctypes available without any major external dependencies. If you love windbg, PyKD is based on WinDBG dbgeng interface to provide debugger automation.  

*Winappdbg/PyKd are great choice when writing fuzzer in python, which most researchers do nowadays. In case someone writing fuzzer in C/C++(?), you still have [Win32 Debugging APIs](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679303(v=vs.85).aspx) or [DbgEng Interface](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/dbgeng/). This is also useful when you are coding fuzzer using any .NET language. Other similar approaches using same technique to do something like [susperius](https://github.com/susperius) written [python extension](https://github.com/susperius/PyFuzzDbg) for exception monitoring using Win32 Apis for his PyFuzz2 fuzzing framework. Again everybody Loves Python!!!* 

> Note:
> 1. Debugger gives us power to monitor all exception before application sees them (first-chance), hence all exception can be caught even when application internally handles them. Also program state information at the time of crash is available. 
> 2. Attaching debugger to heavy processes can be performance penalty.

2. **Postmortem Debugging**
Attaching debugger to process for monitoring exceptions can be expensive in terms of performance. In such case when you don't want to attach debugger but still wants to monitor for crashes, this option can be used as neat trick. 

According "exception handler preference" documented on [msdn](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/enabling-postmortem-debugging) Postmortem debugger is invoked when there is no debugger previously attached and application does not have it's own exception handling routine registered. Below image shows how to set postmortem debugger in registry.
![postm](/content/images/2018/06/postm.png)
Windows invokes postmortem debugger using faulted process id and event id as command line parameters. 

> Note: This will not work when application have it's own structured exception handlers registered to catch runtime expceptions using __try { } __excect { } 

Below is the PoC code for postmortem debugger handler.  

```
int _tmain(int argc, _TCHAR* argv[])
{		
	if (argc == 5)
	{
		//event is argv[4], you need to set to notify WER
		SetEvent((HANDLE)(atol(argv[4])));
		
		//pid is argv[2]
		int pid = atoi(argv[2]);

		//TODO: now you've notification of crashed PID, go ahead and handle for your automation
	}
	return 0;
}
```

3. **DBI exception handler**
This options comes great when you are using dynamic binary instrumentation frameworks such as Intel PIN or DynamoRIO to instrument binary for coverage driven fuzzing/tracing/in-memory fuzzing. 

PoC code as shown below uses intel PIN to instrument binary and monitor exception.
> Note: Consider the overhead of instrumentation

```
VOID OnException(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom, CONTEXT *ctxtTo, INT32 info, VOID *v)
{
	if (reason != CONTEXT_CHANGE_REASON_EXCEPTION)
		return;
	UINT32 exceptionCode = info;
	ADDRINT address = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
	if ((exceptionCode >= 0xc0000000) && (exceptionCode <= 0xcfffffff))
	{
		//TODO: Here you write log, inform server!
		PIN_ExitProcess(-1);
	}
}

int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
    { return Usage(); }
    //TODO: Instrumentation calls
	//add exception handler!
	PIN_AddContextChangeFunction(OnException, 0);
	PIN_StartProgram();
    return 0;
}
```

4. **Windows Error Reporting (WER)**
WER comes handy when monitoring windows universal applications like Edge browser where more complexity is involved for debugging due to additional processing involved. 

Windows Error Reporting is crash reporting mechanism provided by Microsoft. Corporate Error Reporting V2 (MS-CER2) protocol is used to collect WER data and transferred in the form of XML using HTTP POST request. We can have our own local server listening for such crash reports for monitoring purpose. [Msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/bb513638(v=vs.85).aspx) documents WER registry settings used to configure server settings as shown below.
![wer_reg](/content/images/2018/06/wer_reg.png)
Blog post from [Duo labs](https://duo.com/blog/remote-fuzzer-monitoring-with-windows-error-reporting-wer) describes this method in details for Microsoft Edge fault monitoring and also provides PoC python script for parsing WER data. 

**Further Reading In Case You're Wondering How Stuff Works?**
1. [Exception Detection on Windows](http://magazine.hitb.org/hitb-magazine.html) by Gynvael Coldwind is old but great reference to understand internals of windows exceptions.
2. [Windows' User/Kernel exceptions dispatcher](https://doar-e.github.io/blog/2013/10/12/having-a-look-at-the-windows-userkernel-exceptions-dispatcher/)