---
layout: post
title: "Tracing process execution using DBI"
categories: debugging
---

During dynamic analysis of program for malware/vulnerability analysis, it is often necessary to have program trace with concrete execution information for quick grasp of execution flow and its context. Most of the times debuggers are sufficient for such analysis, it is not always the case, specially when analyzing packed/protected binary or when to have this information in external disassembler like IDA. 
This blog post I'll share some notes on such tracing tool I wrote using intel PIN DBI framework and some usecases.

### Instrumentation In Computer Science

In the context of computer programming, instrumentation refers to an ability to monitor or measure the level of a product's performance, to diagnose errors and to write trace information (wikipedia)

### Why do we need instrumentation

Most of the time I use my custom tools written in DBI frameworks to assist on jobs where debuggers are not adequate. Tasks such as noted below can be achived easily with the help of DBI frameworks available out the. 

1. **Debugging** - Runtime analysis of the state programatically. 
2. **Profiling** - Performance analysis 
3. **Tracing** - Generating concrete execution trace to analysis data flow
4. **Coverage Analysis** - Specially when fuzzing, I want to know the code coverage
5. **Control Flow Recovery** - Reversing unknown target, I want to know execution flow
6. **Taint Analysis** - Data flow analysis during crash triage.

### How do we instrument programs

There are two ways to instrument programs, either using static instrumentation or dynamic instrumentation each having it's own advantages and disadvantages. 

1. **Static Instrumentation** - 
For this method, we usually rewrite program during compile time if source code is available or with binary rewriting in case of no source code. 
The advantage of this method is do it once and run many time. Once instrumetation is carried out on target binary it is persistance on disk, this eliminate performance cost at runtime. 
The main disadvantage of this method is for source instrumentation, you need to have access to compilable source code. For binary rewriting, Binary decomposition and reconstruction is still complex problem of software engineering that no known tool gives you 100% results.

    - Source Instrumentation - LLVM compiler passes (example, AFL clang pass)
    - Binary Instrumentation / Binary Rewriting - DynInst, google syzygy (https://github.com/google/syzygy)
2. **Dynamic Instrumentation** - This method on the other hand works at runtime by  translating program and injecting instrumentation callback. There are many well tested frameworks available for DBI.  
   - Debuggers
   - Intel PIN
   - DynamoRIO
   - Frida
   - QDBI

### Writing Tool To Trace Process

The main object of tracer is to help us with all or either of below operation over program execution. 

1. Log module load / unload event
2. Log every basic blocks executed with complete context information
3. Log every call that happened (call instruction)
4. Log every thread creation/termination event
5. Log every instruction with updated context (updated register with memory R/W)
6. Trace only specific module/dll (default to main module)
7. Trace only within specific code boundary (module offsets)

> Note: trace during specific module code range is helpful when you want to analyse only certain function inside target module. Generation full trace is slow operation with few gigs of storage log.

### Writing Tracer Using Debugger - breakpoints and single stepping using winappdbg 
Using plain old debugger apis, you can write quick tracer script for above requirements. Winappdbg/PyKd python frameworks are wrappers around windows debugger apis providing you pythonic scripting access to debugger functionality. below is the python script using winappdbg that traces execution flow to dump context information between specific offsets in wwlib.dll module. 
The disadvantage of this method however is that is is damn slow since we are using breakpoints and single stepping for process tracing. (user -> kernel -> user, if you are aware of the debugger functionality)

```python
class MyEventHandler( EventHandler ):
    def load_dll(self, event):
        module = event.get_module()
        if module.match_name("wwlib.dll"):
            pid = event.get_pid()
            global start, end
            start = module.get_base() + 0x0149103c #0x38732c
            end   = module.get_base() + 0x0149143f  #0x387ab9 
            print "Setting tracepoints at %08x to %08x" % (start, end)
            event.debug.break_at( pid, start, start_tracing )
            event.debug.break_at( pid, end , stop_tracing )
            
    def single_step( self, event ):
        thread = event.get_thread()
        pc     = thread.get_pc()
        global start, end
        if pc >= start and pc <= end:
            print_context_information( thread, block_instructions[pc])
            
with Debug( MyEventHandler(), bKillOnExit = True ) as debug:
	debug.execv( argv )
    debug.loop()
```

### Writing Tracer Using DBI framework - Intel PIN

Intel PIN is one of the popular DBI framework from intel. It has easy and modular API architecture to write DBI client in C++. The usual process of writing DBI client is as follows -      

1. Write DBI client (C/C++) code to instruct instrumentation points and analysis routine using DBI Apis. (This is compiled into DLL with DBI client injects into target process)
2. Run DBI launcher on application with our client 
   *pin.exe -t .\Release\programtracer.dll -i -fo 0x10ac-0x113C -- example.exe*
3. Launcher runs application code by translating it first into local cache with analysis callbacks from our client
4. Instrumentation calls can happens for events such as 
   - Module load/unload
   - Thread start/end
   - Process fork
   - Trace - when new executable trace is discovered

**Analysis routine** - This is callback you insert into interesting events, like in below example, it is called before every basic block.  

  ```c++
  void OnBasicBlock(THREADID tid, ADDRINT addr, UINT32 size, CONTEXT* context)
  {
      ... do analysis here
  }
  ```

**Instrumentation Routine** - This is callback, called by PIN translator when it discovers each trace that is going to be executed. Trace in PIN's terminology is collection of instruction with single entry and multiple exits. (can be many basic blocks in single trace). This is the place where you instruct PIN to insert analysis callback to execute before each basic block. 

  ```c++
  void OnTrace(TRACE trace, void *v)
  {
      for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
  	{
          INS_InsertCall(head, IPOINT_BEFORE, (AFUNPTR)OnBasicBlock, IARG_THREAD_ID, IARG_ADDRINT, BBL_Address(bbl),
  					IARG_UINT32, BBL_Size(bbl), IARG_CONTEXT, IARG_END);
      }
  }
  ```

**Register Instrumentation** - You need to register instrumentation routine to let PIN know you want callback certain interesting events like discovery of TRACE. 

  ```c++
  int  main(int argc, char *argv[])
  {
  	if (PIN_Init(argc, argv))
  		return;	
  	PIN_InitSymbols();
  	TRACE_AddInstrumentFunction(OnTrace, 0);	
  	// Never returns
  	PIN_StartProgram();
  	return 0;
  }
  ```
 
### Intel PIN Granularity - How pin see things in process
If you are somewhat aware of EXE file formats, PIN decompose module at below granularity. 

```
 [Image] [ntdll.dll, kernel32.dll, program.exe ...] IMG_*...
       [Section] [.text, .rdata ...] SEC_*...
			[Routine] RTN_* 
                                [Instruction] INS_*                            
		[Trace] TRACE_*
			[Bbl] BBL_*
				[instruction] INS_*
```

#### Writing Tracer Using PIN 
Quick notes to follow along full source tracer code on github. Source code is already commented wherever required.

1. First we register instrumentation for events including module load/unload, thread start/stop, and trace using IMG_AddInstrumentFunction, IMG_AddUnloadFunction, PIN_AddThreadStartFunction, PIN_AddThreadFiniFunction and TRACE_AddInstrumentFunction functions.
2. In ImageLoad event, along with reporting this event, we also setup offset filters if required.
3. In Trace event, each basic block is iterated and set callback to report execution of basic blocks, every instruction within basic blocks iterated to set callback on each instruction execution (this is where we will dump registers and memory access done by instruction) and finally if any instruction is call instruction, call arguments information dumped. 

Full source code of the tracer https://github.com/shsirk/Conferences/tree/master/BruCON%402018/WinPinTracer

### Running Tracer

**Dump module information**
*pin.exe -t .\Release\programtracer.dll -m -- D:\foo\example.exe*

   ```
   [M] ModuleLoad D:\NullMeet\JACrackme.exe 000001170000-000001185fff
   [M] ModuleLoad C:\Windows\SysWOW64\kernel32.dll 0000746a0000-00007477ffff
   [M] ModuleLoad C:\Windows\SysWOW64\KernelBase.dll 000074800000-0000749e3fff
   [M] ModuleLoad C:\Windows\SysWOW64\ntdll.dll 000077750000-0000778dffff
   [M] ModuleLoad C:\Windows\SysWOW64\user32.dll 000075110000-00007529cfff
   ...
   ```   

**Dump basic blocks and instructions within specific offset**
*pin.exe -t .\Release\programtracer.dll -i -fo 0x10ac-0x113C -- D:\foo\example.exe*

   ```
   [R] 00000000 00000000011710b1  addr=000000000117c118 size=00000004 value=000000007512a860
   [I] 00000000 00000000011710b1 8b 35 18 c1 17 01  mov esi, dword ptr [0x117c118] esi=0000000000731512 eflags=0000000000000246 
   [I] 00000000 00000000011710b7 8d 85 7c ff ff ff lea eax, ptr [ebp-0x84] eax=0000000000000000 ebp=0000000000f8f594 eflags=0000000000000246 
   [I] 00000000 00000000011710bd 68 80 00 00 00 push 0x80 eflags=0000000000000246 
   [W] 00000000 00000000011710bd addr=0000000000f8f3a8 size=00000004 value=0000000000000080
   [I] 00000000 00000000011710c2 50 push eax eax=0000000000f8f510 eflags=0000000000000246 
   [W] 00000000 00000000011710c2 addr=0000000000f8f3a4 size=00000004 value=0000000000f8f510
   ```

### OKAY... now what?

if reversing is your daily task, one of the common tips is to have tracers in your toolkit. Few of the scenarios where it made my life easier - 

1. Have something like time-travel debugging thing, complete trace of the execution and now I can anytime examine traces along with my favourite disassembler to understand behaviour of the program
2. Defeat anti debugging when analyzing hostile code/CTF crackmes
3. Analyze data flow when doing vulnerability research, to answer which instructions/function accessed my data? how data is flowing throughout program?
4. Export this logs to external concolic execution frameworks like Triton to do taint analysis

### What More I Can Do With DBI
Binary instrumentation is largly ignore topic due to complexity involved in writing plugins, although it is not very hard to get familiar with framework apis and build your own interesting plugins. You should explore this area whenever possible. Below are some of the cool things you can achive with DBI.


1. Api Hooking
2. Memory allocation/deallocation tracing
3. Automated malware unpacking
4. Code coverage analysis

   ... and many other things


You can find some the tools I wrote using intel PIN and DynamoRIO and presented at Brucon 2018 in my github repository https://github.com/shsirk/Conferences/tree/master/BruCON%402018

### More reading on this topic

1. https://software.intel.com/sites/landingpage/pintool/docs/97619/Pin/html/index.html
2. http://deniable.org/reversing/binary-instrumentation
3. https://media.blackhat.com/bh-us-11/Diskin/BH_US_11_Diskin_Binary_Instrumentation_Slides.pdf
4. Google is your friends! make query to "Dynamic Binary Instrumentation"
